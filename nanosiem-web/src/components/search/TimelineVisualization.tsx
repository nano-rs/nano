// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState, useEffect, useMemo, useCallback, useRef } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { cn } from '@/lib/utils';
// Parse timestamp string as UTC (handles database format without Z suffix).
// Shared with the asset view.
import { parseTimestampAsUTC } from '@/lib/parse-timestamp-utc';
import {
  ChartColumn,
  TrendingUp,
  Activity,
  LineChart as LineChartIcon,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  AlertTriangle,
  RefreshCw,
  Fingerprint,
  X,
} from 'lucide-react';
import { LoadingIcon } from '@/components/icons/LoadingIcon';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Line,
  LineChart,
  ReferenceArea,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { Button } from '@/components/ui/button';
import {
  PrevalenceScatterPlot,
  type PrevalenceScatterData,
  type PrevalenceSource,
} from '@/components/prevalence/PrevalenceScatterPlot';
import {
  buildDiscoveryQueries,
  buildObservationQueries,
  DOMAIN_PATHS,
  harvestIngestStamps,
  HASH_PATHS,
  mergeDiscoveryResults,
  mergeObservations,
  type DiscoveryResult,
  type InWindowObservation,
  type IngestStamp,
} from '@/lib/prevalence/inWindowObservation';
import { usePrevalenceScatterData } from '@/hooks/use-api';
import { useInternalDomains } from '@/hooks/use-internal-domains';
import { isInternalName } from '@/lib/internal-domains';
import { api, ApiClientError } from '@/lib/api';
import type { ArtifactOccurrence as ApiArtifactOccurrence } from '@/lib/api/types';
import { formatInTimeZone } from 'date-fns-tz';
import { CHART_AXIS_LINE, CHART_AXIS_TEXT } from '@/lib/chart-colors';
import { buildTimelinePlotData, timelinePlotDomain, timelineSeriesData, resolveBucketStart, type TimelinePlotPoint } from './timeline-fill';

interface TimelineDataPoint {
  time: string;
  timestamp: number;
  events: number;
}

// Calculate bucket interval from timeline data
function calculateBucketInterval(data: TimelineDataPoint[]): number {
  if (data.length < 2) return 60 * 1000; // default 1 minute
  // Find the most common interval between consecutive points
  const intervals: number[] = [];
  for (let i = 1; i < data.length; i++) {
    intervals.push(data[i].timestamp - data[i - 1].timestamp);
  }
  // Return the median interval (more robust than average)
  intervals.sort((a, b) => a - b);
  return intervals[Math.floor(intervals.length / 2)] || 60 * 1000;
}

// Short human bucket label for the header subtitle (e.g. "1h", "5m", "30s")
function formatBucketLabel(data: TimelineDataPoint[]): string {
  const ms = calculateBucketInterval(data);
  if (ms >= 86_400_000) return `${Math.round(ms / 86_400_000)}d`;
  if (ms >= 3_600_000) return `${Math.round(ms / 3_600_000)}h`;
  if (ms >= 60_000) return `${Math.round(ms / 60_000)}m`;
  return `${Math.max(1, Math.round(ms / 1000))}s`;
}

// Format Y-axis numbers with abbreviations (K, M) for large values
function formatYAxisTick(value: number): string {
  if (value >= 1_000_000) {
    return `${(value / 1_000_000).toFixed(value % 1_000_000 === 0 ? 0 : 1)}M`;
  }
  if (value >= 1_000) {
    return `${(value / 1_000).toFixed(value % 1_000 === 0 ? 0 : 1)}K`;
  }
  return value.toString();
}

// Custom tooltip for the histogram
interface CustomTooltipProps {
  active?: boolean;
  payload?: Array<{ payload: TimelineDataPoint & { partialLabel?: string | null } }>;
  bucketInterval: number;
  formatTime: (timestamp: number) => string;
}

function HistogramTooltip({ active, payload, bucketInterval, formatTime }: CustomTooltipProps) {
  if (!active || !payload || !payload.length) return null;

  const data = payload[0].payload;
  const startTime = data.timestamp;
  const endTime = startTime + bucketInterval;

  return (
    <div className="bg-popover border border-border rounded-md px-2.5 py-1.5 shadow-[0_8px_24px_rgba(0,0,0,0.25)] font-mono min-w-[140px]">
      <div className="text-[10px] text-muted-foreground tracking-[0.08em] uppercase">
        {formatTime(startTime)} — {formatTime(endTime)} UTC
      </div>
      <div className="text-[13px] font-semibold tabular-nums text-primary mt-0.5">
        {data.events.toLocaleString()}{' '}
        <span className="text-muted-foreground text-[10.5px] font-normal">event{data.events !== 1 ? 's' : ''}</span>
      </div>
      {/* Explain coverage without changing the raw event count. */}
      {data.partialLabel && (
        <div className="text-[10px] text-muted-foreground mt-0.5">{data.partialLabel}</div>
      )}
    </div>
  );
}

interface SearchResult {
  id: string;
  timestamp: Date;
  source: string;
  fields: Record<string, unknown>;
}

/**
 * Artifact occurrence with event timestamp from search results
 */
interface ArtifactOccurrence {
  artifact: string;
  eventTimestamp: Date;
  occurrenceCount: number;
}

interface BaselinePrevalence {
  hostCount: number;
  isRare: boolean;
  prevalenceScore: number;
  totalOccurrences: number;
  envFirstSeen: Date;
}

/**
 * Assemble one scatter point from the three prevalence sources.
 *
 * NAN-2361 precedence, and the reasoning behind it:
 *
 * The BASELINE wins whenever it has an answer, even if the in-window count is
 * larger. "Is this rare in my environment?" is a question about history — an
 * asset that touched the artifact yesterday sits outside a one-hour search
 * window, so the in-window number is a strict LOWER BOUND on environment
 * prevalence and would understate exactly the case an analyst must not
 * underestimate.
 *
 * The IN-WINDOW count is the fallback for artifacts the baseline has never
 * heard of — the minutes-old-alert case that motivated this work. It is
 * flagged `in-window` so the plot can draw it hollow and the tooltip can say
 * it is window-scoped, rather than passing it off as environment truth.
 *
 * `max()` across the two was considered and rejected: both are lower bounds so
 * the larger is technically the better estimate, but it produces a number whose
 * measurement period is unstated, which is how a chart loses an analyst's
 * trust. Two labelled numbers beat one ambiguous one.
 */
function buildPoint(
  occ: ArtifactOccurrence,
  artifactType: 'hash' | 'domain',
  baseline: BaselinePrevalence | undefined,
  observation: InWindowObservation | undefined,
  stamp: IngestStamp | undefined,
  rarityThreshold: number,
): PrevalenceScatterData['hashPoints'][number] {
  const inWindowHosts = observation?.hosts;
  const isNewAtIngest = stamp?.isNew === true;
  // Pin the novelty cue to the artifact's earliest occurrence. `is_new` is
  // stamped on EVERY occurrence during the snapshot catch-up, so without this
  // one new artifact rings every dot it owns.
  const isEarliestOccurrence =
    stamp?.earliestMs == null || occ.eventTimestamp.getTime() <= stamp.earliestMs;
  // `occ.eventTimestamp` only reflects rows the search page actually loaded
  // (top-N by recency), so under any volume that exceeds the page size every
  // artifact's "first occurrence" collapses to the tail of the window. The
  // in-window observation's `firstInWindow` comes from an unbounded
  // `min(time)` aggregate over the SAME window and is not subject to that
  // truncation -- prefer it whenever it's available.
  const firstSeen =
    observation?.firstInWindow != null ? new Date(observation.firstInWindow) : occ.eventTimestamp;

  if (baseline) {
    return {
      artifact: occ.artifact,
      artifactType,
      hostCount: baseline.hostCount,
      firstSeen,
      lastSeen: occ.eventTimestamp,
      totalOccurrences: occ.occurrenceCount,
      isRare: baseline.isRare,
      prevalenceScore: baseline.prevalenceScore,
      // NAN-1699: no event-time fallback — "new to env" must key off a REAL
      // env-first-seen, not the occurrence time, or every miss looks new.
      envFirstSeen: baseline.envFirstSeen,
      prevalenceSource: 'baseline',
      baselineHostCount: baseline.hostCount,
      inWindowHosts,
      inWindowEvents: observation?.events,
    };
  }

  if (inWindowHosts != null && inWindowHosts > 0) {
    return {
      artifact: occ.artifact,
      artifactType,
      hostCount: inWindowHosts,
      firstSeen,
      lastSeen: occ.eventTimestamp,
      totalOccurrences: occ.occurrenceCount,
      // Rarity against the same threshold the baseline uses, so the colour
      // means the same thing on both. The COUNT's provenance differs, which is
      // what the hollow fill and the tooltip communicate.
      isRare: inWindowHosts < rarityThreshold,
      prevalenceScore: 0,
      envFirstSeen: undefined,
      prevalenceSource: 'in-window',
      inWindowHosts,
      inWindowEvents: observation?.events,
      isNewAtIngest: isNewAtIngest && isEarliestOccurrence,
    };
  }

  return {
    artifact: occ.artifact,
    artifactType,
    hostCount: 0,
    firstSeen,
    lastSeen: occ.eventTimestamp,
    totalOccurrences: occ.occurrenceCount,
    isRare: false,
    prevalenceScore: 0,
    envFirstSeen: undefined,
    prevalenceSource: 'none',
    inWindowHosts,
    inWindowEvents: observation?.events,
  };
}


// NAN-1701: a dotted string is only a trackable DOMAIN artifact if its last
// label is a plausible public TLD — otherwise filenames (`BGInfo.bmp`,
// `kernel32.dll`), internal hostnames (`ws-01.corp.local`) and the like get
// plotted as domains the prevalence agg can never baseline, flooding the rarity
// scatter with fake "not baselined" dots. The internal-TLD set mirrors the
// backend domain-prevalence MV's exclusion (migration 129); the file-extension
// set catches Windows telemetry noise.
// NOTE: deliberately EXCLUDES anything that is also a real public TLD —
// `.com/.zip/.mov` are gTLDs, `.so/.md/.sh/.py/.pl/.cab` are ccTLDs/gTLDs — so we
// only list extensions that are unambiguously NOT delegated TLDs. A file with a
// TLD-shaped extension (`evil.sh`) will slip through as a "domain"; that's the
// safe failure (over-include rare junk) vs dropping every `.com` domain.
const NON_DOMAIN_LAST_LABELS = new Set([
  // internal / non-public TLDs (match backend domain_prevalence_*_mv)
  'local', 'corp', 'internal', 'lan', 'home', 'localdomain', 'intranet', 'private', 'arpa',
  // file extensions that are NOT real TLDs
  'exe', 'dll', 'sys', 'bin', 'dat', 'tmp', 'temp', 'log', 'txt', 'ini', 'cfg', 'conf',
  'xml', 'json', 'yaml', 'bmp', 'png', 'jpg', 'jpeg', 'gif', 'ico', 'msi', 'bat', 'vbs',
  'cmd', 'scr', 'pif', 'jar', 'rar', 'tar', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt',
  'pptx', 'csv', 'bak', 'lnk', 'mui', 'nls', 'tlb', 'ocx', 'cpl', 'drv', 'dylib', 'crt',
  'pfx', 'class',
]);

function isTrackableDomain(value: string, internalSuffixes: readonly string[] = []): boolean {
  if (!value.includes('.') || value.includes(' ')) return false;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) return false; // IPv4
  const labels = value.split('.');
  const tld = labels[labels.length - 1].toLowerCase();
  // Public TLDs are alphabetic and 2+ chars; reject numeric/short and the
  // internal-TLD / file-extension blocklist.
  if (tld.length < 2 || !/^[a-z]{2,24}$/.test(tld)) return false;
  if (NON_DOMAIN_LAST_LABELS.has(tld)) return false;
  // NAN-3226: names under a tenant internal suffix (Settings → Risk) are
  // internal hosts — the prevalence agg excludes them, so never plot them.
  return !isInternalName(value, internalSuffixes);
}

// NAN-1701: rarity is a small-window tool. Auto-populate only for searches this
// short; larger windows (which in a busy estate can extract tens of thousands of
// artifacts) require an explicit "Load rarity" click.
const RARITY_AUTO_MAX_HOURS = 4;
// Hard ceiling on artifacts scored per search — a runaway `*`-over-a-week result
// set can't fire hundreds of requests or drop tens of thousands of SVG dots.
const RARITY_MAX_ARTIFACTS = 1000;
const RARITY_BATCH_SIZE = 100; // == backend MAX_BULK_ARTIFACTS
// NAN-2361: `limit` caps GROUPS on an aggregate, not events. Must clear the
// per-query artifact count or artifacts silently vanish from the result.
const OBSERVATION_LIMIT = 250;
// NAN-2361: discovery asks "which artifacts appear" with no artifact filter,
// so its `limit` caps distinct-artifact CARDINALITY for the search, not raw
// events -- at real ingest volume this covers the whole window where the old
// raw-row extraction covered a few seconds of it. `_FULL` is the ceiling for
// an explicit "load all artifacts" click: still bounded (an unfiltered `*`
// over a huge window can have very high cardinality), just far higher than
// the default.
const DISCOVERY_LIMIT = 500;
const DISCOVERY_LIMIT_FULL = 10000;
const RARITY_MAX_CONCURRENT = 6; // cap parallel prevalence batches (API service)
// NAN-2361: the SEARCH service admission-controls at 5 concurrent queries per
// user, and over-limit requests 429 IMMEDIATELY (no queueing). Discovery fires
// 3 hash + 4 domain queries while the page's own search / artifact fetch can
// still be in flight, so a cap of 6 guaranteed 429s — and a 429'd path used to
// degrade silently to "found nothing". Keep search-service fan-out at 3 to
// leave admission headroom, and retry throttled queries (below).
const SEARCH_MAX_CONCURRENT = 3;

// Retry a search that was refused by admission control (429 / ADMISSION_DENIED).
// The refusal is instantaneous, so a short backoff while sibling queries drain
// almost always succeeds; anything else (real errors) is NOT retried.
async function searchWithRetry(
  req: Parameters<typeof api.search>[0],
): Promise<Awaited<ReturnType<typeof api.search>>> {
  for (let attempt = 0; ; attempt++) {
    try {
      return await api.search(req);
    } catch (err) {
      const throttled =
        err instanceof ApiClientError && (err.status === 429 || err.code === 'ADMISSION_DENIED');
      if (!throttled || attempt >= 3) throw err;
      await new Promise((r) => setTimeout(r, 350 * 2 ** attempt + Math.random() * 250));
    }
  }
}

// Run `fn` over `items` with at most `limit` in flight; preserves input order.
async function mapLimit<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, async () => {
      while (next < items.length) {
        const i = next++;
        out[i] = await fn(items[i]);
      }
    }),
  );
  return out;
}

/**
 * Extract unique hashes and domains from search results WITH their event timestamps.
 * This ensures the chart shows artifacts at the time they appeared in the search results,
 * not at the global first/last seen times from prevalence aggregation.
 */
function extractArtifactsWithTimestamps(
  results: SearchResult[],
  internalSuffixes: readonly string[] = [],
): {
  hashes: string[];
  domains: string[];
  hashOccurrences: ArtifactOccurrence[];
  domainOccurrences: ArtifactOccurrence[];
  droppedCount: number;
} {
  const hashes = new Set<string>();
  const domains = new Set<string>();

  // Per-event occurrences — one dot per event, no deduplication.
  // This lets users click individual dots to navigate to the underlying event.
  const hashOccurrences: ArtifactOccurrence[] = [];
  const domainOccurrences: ArtifactOccurrence[] = [];

  // Handle asset view: events are nested in _asset_events
  let eventsToProcess: Array<{ timestamp: Date; fields: Record<string, unknown> }> = [];

  if (results.length === 1 && results[0]?.fields?._display_type === 'asset') {
    // Asset view - extract from individual _asset_events so each event gets its own dot
    const assetEvents = results[0].fields._asset_events as Array<{ timestamp: string; details?: Record<string, unknown> }> | undefined;
    if (assetEvents) {
      eventsToProcess = assetEvents.map(e => ({
        timestamp: parseTimestampAsUTC(e.timestamp),
        fields: e.details || (e as unknown as Record<string, unknown>),
      }));
    }
  } else {
    // Normal search results
    eventsToProcess = results.map(r => ({
      timestamp: r.timestamp,
      fields: r.fields || {},
    }));
  }

  for (const event of eventsToProcess) {
    const fields = event.fields;
    if (!fields) continue;

    const eventTimestamp = event.timestamp;
    // Dedup within the same event (same artifact extracted from multiple fields)
    const seenInEvent = new Set<string>();

    // Helper to add hash with timestamp
    const addHash = (hash: unknown) => {
      if (hash && typeof hash === 'string' && hash.length >= 32 && /^[a-fA-F0-9]{32,64}$/.test(hash)) {
        const normalizedHash = hash.toLowerCase();
        hashes.add(normalizedHash);

        const eventKey = `h_${normalizedHash}`;
        if (!seenInEvent.has(eventKey)) {
          seenInEvent.add(eventKey);
          hashOccurrences.push({
            artifact: normalizedHash,
            eventTimestamp,
            occurrenceCount: 1,
          });
        }
      }
    };

    // Helper to add domain with timestamp
    const addDomain = (domain: unknown) => {
      if (domain && typeof domain === 'string' && isTrackableDomain(domain, internalSuffixes)) {
        const normalizedDomain = domain.toLowerCase();
        domains.add(normalizedDomain);

        const eventKey = `d_${normalizedDomain}`;
        if (!seenInEvent.has(eventKey)) {
          seenInEvent.add(eventKey);
          domainOccurrences.push({
            artifact: normalizedDomain,
            eventTimestamp,
            occurrenceCount: 1,
          });
        }
      }
    };

    // NAN-2361: OCSF/lake rows carry NONE of the UDM field names below, so the
    // rarity chart extracted nothing and rendered permanently empty on a lake
    // tenant. OCSF nests hashes in `<obj>.hashes[]` arrays and hostnames under
    // endpoint/url/query objects. Both vocabularies are read so one component
    // serves UDM, OCSF-on-ClickHouse and the lake.
    const atPath = (root: unknown, path: string): unknown => {
      let cur: unknown = root;
      for (const part of path.split('.')) {
        if (!cur || typeof cur !== 'object') return undefined;
        cur = (cur as Record<string, unknown>)[part];
      }
      return cur;
    };
    // `hashes` is an array of {algorithm, value} objects in OCSF.
    const addOcsfHashes = (path: string) => {
      const arr = atPath(fields, path);
      if (Array.isArray(arr)) {
        for (const h of arr) {
          if (h && typeof h === 'object') addHash((h as Record<string, unknown>).value);
        }
      }
    };
    for (const p of ['file.hashes', 'process.file.hashes', 'actor.process.file.hashes']) {
      addOcsfHashes(p);
    }

    // Extract file hashes
    addHash(fields.file_hash);
    addHash(fields.process_hash);

    // Also check for hashes in metadata
    const metadata = fields.metadata as Record<string, unknown> | undefined;
    if (metadata) {
      addHash(metadata.file_hash);
      addHash(metadata.process_hash);
    }

    // Helper to extract domain from URL
    const extractDomainFromUrl = (url: unknown) => {
      if (!url || typeof url !== 'string') return;
      try {
        // Handle URLs with protocol
        if (url.startsWith('http://') || url.startsWith('https://')) {
          const urlObj = new URL(url);
          addDomain(urlObj.hostname);
        }
      } catch {
        // Not a valid URL, ignore
      }
    };

    // Extract domains from various fields
    addDomain(fields.dest_host);
    addDomain(fields.dest_domain);
    addDomain(fields.domain);
    addDomain(fields.query);       // DNS queries (Sysmon Event 22)
    addDomain(fields.url_domain);  // Proxy/web logs
    addDomain(fields.http_host);   // HTTP Host header

    // OCSF hostname surfaces (see the note above).
    for (const p of [
      'dst_endpoint.hostname',
      'src_endpoint.hostname',
      'url.hostname',
      'query.hostname',
      'http_request.url.hostname',
    ]) {
      addDomain(atPath(fields, p));
    }
    extractDomainFromUrl(atPath(fields, 'url.url_string'));
    extractDomainFromUrl(atPath(fields, 'http_request.url.url_string'));

    // Extract domains from URL fields
    extractDomainFromUrl(fields.url);
    extractDomainFromUrl(fields.http_referrer);
    extractDomainFromUrl(fields.file_path);  // Sometimes contains URLs
  }

  // NAN-1701: no arbitrary 50-cap — an analyst must see every artifact. The only
  // bound is the RARITY_MAX_ARTIFACTS ceiling (a runaway-result-set backstop),
  // applied HERE so lookup, plotting, and the SVG are all consistent — dropping
  // it from the lookup but still plotting it would just resurrect fake host-0
  // dots. Prioritize hashes, fill remaining budget with domains; keep only the
  // occurrences of kept artifacts. droppedCount drives the "showing N of M" badge.
  const allHashes = Array.from(hashes);
  const allDomains = Array.from(domains);
  const keptHashes = allHashes.slice(0, RARITY_MAX_ARTIFACTS);
  const keptDomains = allDomains.slice(0, Math.max(0, RARITY_MAX_ARTIFACTS - keptHashes.length));
  const droppedCount = allHashes.length + allDomains.length - keptHashes.length - keptDomains.length;
  if (droppedCount === 0) {
    return { hashes: keptHashes, domains: keptDomains, hashOccurrences, domainOccurrences, droppedCount };
  }
  const kept = new Set<string>([...keptHashes, ...keptDomains]);
  return {
    hashes: keptHashes,
    domains: keptDomains,
    hashOccurrences: hashOccurrences.filter((o) => kept.has(o.artifact)),
    domainOccurrences: domainOccurrences.filter((o) => kept.has(o.artifact)),
    droppedCount,
  };
}

type VisualizationMode = 'timeline' | 'prevalence';

interface TimelineVisualizationProps {
  timelineData: TimelineDataPoint[];
  eventCount: number;
  collapsed: boolean;
  onToggleCollapsed: () => void;
  chartType: 'bar' | 'line' | 'area';
  onChartTypeChange: (type: 'bar' | 'line' | 'area') => void;
  onZoomIn: () => void;
  onZoomOut: () => void;
  onResetZoom: () => void;
  onTimelineClick: (data: { activePayload?: Array<{ payload: { timestamp?: number } }> }) => void;
  refAreaLeft: string | number | null;
  refAreaRight: string | number | null;
  onMouseDown: (e: { activeLabel?: string | number }) => void;
  onMouseMove: (e: { activeLabel?: string | number }) => void;
  onMouseUp: () => void;
  results: SearchResult[];
  hasSearched: boolean;
  onArtifactFilter?: (artifact: string, artifactType: 'hash' | 'domain', timestamp?: Date) => void;
  onSelectionFilter?: (artifacts: string[]) => void;
  timeWindow?: string;
  query?: string;
  timeRange?: { start: string; end: string };
  /**
   * NAN-3254: the window the chart plots, when it differs from `timeRange`
   * (live tail slides it to now). Only the x-axis / partial-bucket window
   * reads it; fetches stay keyed on `timeRange`.
   */
  plotRange?: { start: string; end: string };
  resultCount?: number;
  /** Static mode: hides zoom controls, prevalence toggle, and drag-to-select. Used for timechart results. */
  staticMode?: boolean;
  /** Title override for the card header */
  title?: string;
  /** Asset mode: prevalence clicks filter the asset timeline instead of modifying query */
  isAssetMode?: boolean;
  /** Callback to clear asset prevalence filter */
  onClearAssetFilter?: () => void;
  /** Whether an asset filter is currently active */
  assetFilterActive?: boolean;
  /** Asset context for fetching full artifact summaries (required in asset mode for prevalence) */
  assetContext?: {
    identifier_field: string;
    identifier_value: string;
    identities: Record<string, unknown>[];
  };
}

export function TimelineVisualization({
  timelineData,
  eventCount,
  collapsed,
  onToggleCollapsed,
  chartType,
  onChartTypeChange,
  onZoomIn,
  onZoomOut,
  onResetZoom,
  onTimelineClick,
  refAreaLeft,
  refAreaRight,
  onMouseDown,
  onMouseMove,
  onMouseUp,
  results,
  hasSearched,
  onArtifactFilter,
  onSelectionFilter,
  timeWindow = '30d',
  query: _query,
  timeRange,
  plotRange,
  resultCount,
  staticMode = false,
  title,
  isAssetMode = false,
  onClearAssetFilter,
  assetFilterActive = false,
  assetContext,
}: TimelineVisualizationProps) {
  // `view=rarity` URL param stickies the Rarity tab across share-links. Absent param
  // or any other value keeps the default Timeline view. Asset mode always starts in
  // prevalence and ignores the URL (the asset detail route owns its own URL shape).
  const [searchParams, setSearchParams] = useSearchParams();
  const urlWantsRarity = searchParams.get('view') === 'rarity';
  const [mode, setMode] = useState<VisualizationMode>(
    isAssetMode || urlWantsRarity ? 'prevalence' : 'timeline'
  );
  const [scatterData, setScatterData] = useState<PrevalenceScatterData | null>(null);
  // NAN-1701: user explicitly loaded rarity for a large (>4h) window. (The
  // ceiling-dropped count for the badge comes from extractedData.droppedCount.)
  const [rarityManualLoad, setRarityManualLoad] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const lastFetchedKeyRef = useRef<string | null>(null);
  // Monotonic id for `loadScatterData` invocations; a run only commits its
  // results while it is still the newest. See the guard at its top.
  const scatterRunRef = useRef(0);
  // Key of the run currently in flight, or null when nothing is running. The
  // dedup guards need it: "already fetched this key" is only a safe skip when
  // no DIFFERENT key is still in flight behind it.
  const activeRunKeyRef = useRef<string | null>(null);
  // Track the max host count for server-side re-fetch in asset mode
  // Default high so the chart isn't empty — analysts can drag down to focus on rare artifacts
  const [assetMaxHostCount, setAssetMaxHostCount] = useState(10000);

  // Sync mode when isAssetMode changes (useState initializer only runs on mount)
  useEffect(() => {
    setMode(isAssetMode ? 'prevalence' : urlWantsRarity ? 'prevalence' : 'timeline');
    // urlWantsRarity intentionally omitted from deps — we only want this to sync on
    // isAssetMode transitions. URL→mode is already handled by the initializer, and
    // mode→URL is handled below.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isAssetMode]);

  // Sync mode → URL (skip for asset mode, which doesn't own the search URL).
  useEffect(() => {
    if (isAssetMode) return;
    const current = searchParams.get('view');
    const desired = mode === 'prevalence' ? 'rarity' : null;
    if (current === desired) return;
    const next = new URLSearchParams(searchParams);
    if (desired) next.set('view', desired);
    else next.delete('view');
    setSearchParams(next, { replace: true });
  }, [mode, isAssetMode, searchParams, setSearchParams]);

  const { mutate: fetchScatterData } = usePrevalenceScatterData();
  // Stable ref for fetchScatterData — useMutation returns a new function identity
  // every render (because .bind() creates a new ref), which would cascade into
  // loadScatterData getting a new identity → trigger effect re-firing → double fetch.
  const fetchScatterDataRef = useRef(fetchScatterData);
  fetchScatterDataRef.current = fetchScatterData;

  // Extract artifacts WITH timestamps from search results.
  //
  // NAN-1689: the default results view is fetched with `table_view=true` (a slim
  // ~11-column projection for fast load) which PRUNES process_hash/file_hash/
  // domain columns — so the slim `results` almost never yield artifacts and the
  // Rarity view would be permanently empty. We keep the table view slim (perf)
  // and instead fetch a full-field page on demand when Rarity is opened and the
  // slim rows carry no artifacts, then extract from that.
  const internalSuffixes = useInternalDomains();
  const slimExtracted = useMemo(
    () => extractArtifactsWithTimestamps(results, internalSuffixes),
    [results, internalSuffixes],
  );
  const slimHasArtifacts = slimExtracted.hashes.length > 0 || slimExtracted.domains.length > 0;

  // Stable identity for the current query + window. The on-demand fetch below is
  // keyed on this so a previous query's rows are NEVER reused for a newer one
  // (fetches are async — the query can change before one resolves).
  const artifactFetchKey = useMemo(
    () =>
      _query && timeRange?.start && timeRange?.end
        ? `${_query}|${timeRange.start}|${timeRange.end}`
        : null,
    [_query, timeRange],
  );

  const [fetchedArtifacts, setFetchedArtifacts] = useState<{ key: string; rows: SearchResult[] } | null>(null);
  const [artifactFetchLoading, setArtifactFetchLoading] = useState(false);
  const artifactFetchKeyRef = useRef<string | null>(null);

  useEffect(() => {
    // Only needed when Rarity is open, the slim rows lack artifacts, and this is
    // a normal (non-asset) query we can re-run. Asset mode fetches its own
    // artifact summaries via `assetContext`.
    if (mode !== 'prevalence' || isAssetMode || slimHasArtifacts || !artifactFetchKey) return;
    if (artifactFetchKeyRef.current === artifactFetchKey) return; // already fetched/attempted
    artifactFetchKeyRef.current = artifactFetchKey;
    setArtifactFetchLoading(true);
    let cancelled = false;
    api
      .search({
        query: _query!,
        time_range: timeRange!,
        limit: 500,
        table_view: false, // full projection so process_hash/file_hash/domains are present
        skip_field_stats: true,
        skip_histogram: true,
      })
      .then((resp) => {
        if (cancelled) return;
        const rows: SearchResult[] = (resp.results || [])
          .filter((r): r is Record<string, unknown> => r != null && typeof r === 'object')
          .map((r, i) => ({
            id: `rarity-${i}`,
            timestamp: parseTimestampAsUTC(r.timestamp as string | undefined),
            source: String(r.src_host ?? r.src_ip ?? 'unknown'),
            fields: r,
          }));
        setFetchedArtifacts({ key: artifactFetchKey, rows });
      })
      .catch(() => {
        if (cancelled) return;
        // Reset the key so a transient failure can be retried (e.g. by toggling
        // back to Rarity) rather than wedging the tab until the query changes.
        if (artifactFetchKeyRef.current === artifactFetchKey) artifactFetchKeyRef.current = null;
      })
      .finally(() => {
        if (!cancelled) setArtifactFetchLoading(false);
      });
    return () => {
      cancelled = true;
      // Same wedge as the discovery effect below: a cancelled run must release
      // the claims it made before fetching, or the flag stays true and the key
      // stays claimed forever.
      if (artifactFetchKeyRef.current === artifactFetchKey) artifactFetchKeyRef.current = null;
      setArtifactFetchLoading(false);
    };
  }, [mode, isAssetMode, slimHasArtifacts, artifactFetchKey, _query, timeRange]);

  // NAN-2361: which artifacts exist in this window, discovered by an aggregate
  // (`stats ... by <path>`) over the caller's OWN query -- no artifact filter,
  // no raw-row extraction. `limit` here bounds distinct-artifact CARDINALITY,
  // not events, so it covers the real window at real ingest volume instead of
  // a few seconds of it (see DISCOVERY_LIMIT). Supersedes raw-row extraction
  // as the artifact-list source; `fetchedArtifacts` above still runs and now
  // serves only `rarityRows` (ingest-stamp / novelty harvesting below).
  // "Load all" opt-in is KEYED to the query+window it was clicked for: a new
  // search must fall back to the default limit rather than silently inheriting
  // a prior query's 10,000-group opt-in. (A plain boolean reset via effect
  // would still let the discovery effect fire once at the stale FULL limit
  // before the reset committed.)
  const [discoveryLoadAllKey, setDiscoveryLoadAllKey] = useState<string | null>(null);
  const discoveryLoadAll = discoveryLoadAllKey != null && discoveryLoadAllKey === artifactFetchKey;
  const [discovered, setDiscovered] = useState<{
    key: string;
    hash: DiscoveryResult;
    domain: DiscoveryResult;
  } | null>(null);
  const [discoveryLoading, setDiscoveryLoading] = useState(false);
  const discoveryKeyRef = useRef<string | null>(null);
  // Bumped by the failure banner's retry button to re-run an incomplete discovery.
  const [discoveryRetryNonce, setDiscoveryRetryNonce] = useState(0);

  useEffect(() => {
    // NAN-2361: aggregate discovery runs even when the LOADED rows already
    // carry artifacts.
    //
    // `slimHasArtifacts` describes the current PAGE, not the result set. Gating
    // on it meant one artifact anywhere in the loaded rows suppressed the
    // aggregate entirely, and the chart then plotted only that page's artifacts
    // while presenting itself as the environment view — every artifact outside
    // the loaded page silently missing. The full-field page fetch above still
    // uses the flag (it exists only to recover pruned columns); completeness of
    // the artifact SET is this query's job.
    if (mode !== 'prevalence' || isAssetMode || !artifactFetchKey || !_query) return;
    const limit = discoveryLoadAll ? DISCOVERY_LIMIT_FULL : DISCOVERY_LIMIT;
    const effectiveKey = `${artifactFetchKey}|${limit}`;
    if (discoveryKeyRef.current === effectiveKey) return;
    discoveryKeyRef.current = effectiveKey;
    setDiscoveryLoading(true);
    let cancelled = false;

    // ONE bounded pool across hash + domain paths — two parallel pools of 6
    // meant 7 concurrent searches against a 5-per-user admission limit, so at
    // least two paths 429'd on EVERY discovery run and silently dropped out.
    const hashQueries = buildDiscoveryQueries(_query!, HASH_PATHS);
    const domainQueries = buildDiscoveryQueries(_query!, DOMAIN_PATHS);
    mapLimit([...hashQueries, ...domainQueries], SEARCH_MAX_CONCURRENT, async (q) => {
      try {
        const resp = await searchWithRetry({
          query: q.npl,
          time_range: timeRange!,
          limit,
          skip_histogram: true,
        });
        return {
          path: q.path,
          rows: (resp.results ?? []) as Record<string, unknown>[],
          totalCount: resp.total_count ?? null,
        };
      } catch {
        // Discovery is an enhancement; a failed path never breaks the chart —
        // but it is NOT "found nothing": mark it so the UI can say the list
        // is incomplete (a bare empty result here used to be indistinguishable
        // from a genuinely artifact-free path).
        return { path: q.path, rows: [], totalCount: null, failed: true };
      }
    })
      .then((results) => {
        if (cancelled) return;
        const hash = mergeDiscoveryResults(results.slice(0, hashQueries.length));
        const domain = mergeDiscoveryResults(results.slice(hashQueries.length));
        setDiscovered({ key: effectiveKey, hash, domain });
      })
      .catch(() => {
        if (cancelled) return;
        if (discoveryKeyRef.current === effectiveKey) discoveryKeyRef.current = null;
      })
      .finally(() => {
        if (!cancelled) setDiscoveryLoading(false);
      });
    return () => {
      cancelled = true;
      // Release BOTH claims this run made, or a cancelled run wedges the tab.
      //
      // The run marks the key as attempted and flips the loading flag before
      // fetching, but `.finally` is guarded by `!cancelled` — so switching away
      // from Rarity mid-flight (or any re-render handing down a new `timeRange`
      // identity) tore the effect down with `discoveryLoading` stuck true and
      // the key stuck claimed. Coming back rendered the spinner branch forever:
      // no chart, no empty state, and neither retry button reachable, since both
      // live in branches that require a `discoveryResult`.
      if (discoveryKeyRef.current === effectiveKey) discoveryKeyRef.current = null;
      setDiscoveryLoading(false);
    };
  }, [mode, isAssetMode, artifactFetchKey, _query, timeRange, discoveryLoadAll, discoveryRetryNonce]);

  const discoveryResult =
    discovered && discovered.key === `${artifactFetchKey}|${discoveryLoadAll ? DISCOVERY_LIMIT_FULL : DISCOVERY_LIMIT}`
      ? discovered
      : null;

  // Only trust fetched rows that belong to the CURRENT query + window; a stale
  // set from a prior query is ignored (→ empty until the new fetch resolves).
  const extractedData = useMemo(() => {
    // NAN-2361: discovery WINS whenever it has landed, including when the
    // loaded page already carries artifacts.
    //
    // Preferring `slimExtracted` in that case reintroduced the very bug the
    // discovery effect above was un-gated to fix: the effect now always runs,
    // but its result was discarded the moment one artifact appeared in the
    // loaded rows, so the chart still plotted a page-local subset while
    // presenting itself as the environment view. `slimExtracted` stays as the
    // PROGRESSIVE fallback — something to render while discovery is in flight
    // (or if it never resolves) — not as the preferred source.
    if (!discoveryResult) {
      return slimHasArtifacts
        ? slimExtracted
        : { hashes: [], domains: [], hashOccurrences: [], domainOccurrences: [], droppedCount: 0 };
    }
    // Discovery groups on WHATEVER value the field holds — unlike the raw-row
    // path (`addHash`/`isTrackableDomain` below), there's no per-row client
    // filter before a group key becomes an artifact. `dst_endpoint.hostname`
    // et al. are frequently the placeholder `"-"` when no hostname exists for
    // that event; without this filter it group-bys into a "rare, 1-host,
    // not-yet-baselined" dot that isn't a real artifact at all.
    const toOccurrences = (
      result: DiscoveryResult,
      isValid: (artifact: string) => boolean,
    ): ArtifactOccurrence[] =>
      Array.from(result.observations.entries())
        .filter(([artifact]) => isValid(artifact))
        .map(([artifact, obs]) => ({
          artifact,
          // No `min(time)` for the group: anchor to the window start, not to
          // "now". The artifact demonstrably occurred somewhere in this window,
          // so the window's left edge is the honest lower bound; `new Date()`
          // would place it at the right edge and read as a fresh sighting.
          eventTimestamp:
            obs.firstInWindow != null
              ? new Date(obs.firstInWindow)
              : parseTimestampAsUTC(timeRange?.start),
          occurrenceCount: obs.events || 1,
        }));
    const allHashes = toOccurrences(discoveryResult.hash, (a) => /^[a-fA-F0-9]{32,64}$/.test(a));
    const allDomains = toOccurrences(discoveryResult.domain, (a) => isTrackableDomain(a, internalSuffixes));
    const keptHashes = allHashes.slice(0, RARITY_MAX_ARTIFACTS).map((o) => o.artifact);
    const keptDomains = allDomains
      .slice(0, Math.max(0, RARITY_MAX_ARTIFACTS - keptHashes.length))
      .map((o) => o.artifact);
    const kept = new Set([...keptHashes, ...keptDomains]);
    const droppedCount = allHashes.length + allDomains.length - kept.size;
    return {
      hashes: keptHashes,
      domains: keptDomains,
      hashOccurrences: allHashes.filter((o) => kept.has(o.artifact)),
      domainOccurrences: allDomains.filter((o) => kept.has(o.artifact)),
      droppedCount,
    };
  }, [slimHasArtifacts, slimExtracted, discoveryResult, timeRange, internalSuffixes]);

  // NAN-2361: the rows the ingest stamps are harvested from. Unlike the artifact
  // LIST (which discovery owns), a stamp is a per-source earliest-ingest time —
  // any loaded rows for this query carry it, so preferring already-loaded
  // `results` over a second fetch costs nothing in correctness.
  const rarityRows: SearchResult[] = useMemo(() => {
    if (slimHasArtifacts) return results;
    return fetchedArtifacts && fetchedArtifacts.key === artifactFetchKey
      ? fetchedArtifacts.rows
      : [];
  }, [slimHasArtifacts, results, fetchedArtifacts, artifactFetchKey]);
  // NAN-2361: truncation is now an ARTIFACT-cardinality signal from discovery
  // (`total_count` on the aggregate vs rows returned), not an events-loaded
  // signal -- a query can load a "sample" of 500 events yet discover its
  // complete artifact population, or vice versa. It is no longer suppressed
  // when the page happens to hold artifacts: discovery now owns the list in
  // that case too, so its truncation is the honest signal for what is plotted.
  const rarityTruncated =
    !isAssetMode && !!discoveryResult &&
    (discoveryResult.hash.truncated || discoveryResult.domain.truncated);
  const rarityTotalArtifacts = discoveryResult
    ? discoveryResult.hash.totalArtifacts + discoveryResult.domain.totalArtifacts
    : 0;
  // Paths whose discovery query failed even after 429 retries: the artifact
  // list is incomplete in a way the truncation banner cannot express (a failed
  // path reports totalCount null and never trips `truncated`).
  const discoveryFailedPaths = discoveryResult
    ? [...discoveryResult.hash.failedPaths, ...discoveryResult.domain.failedPaths]
    : [];
  const hasArtifacts = extractedData.hashes.length > 0 || extractedData.domains.length > 0;

  // NAN-1700 progressive render: pending scatter points derived purely from the
  // extracted occurrences (event time + count), with no prevalence yet. Shown
  // immediately at their event times on the baseline while the (slow) rarity
  // lookup runs; the enriched `scatterData` replaces them when it lands and the
  // dots animate up to their real rarity Y / color. Search mode only — asset
  // mode gets its per-event points straight from the backend.
  const pendingScatterData = useMemo<PrevalenceScatterData | null>(() => {
    if (isAssetMode) return null;
    if (!extractedData.hashOccurrences.length && !extractedData.domainOccurrences.length) return null;
    const toPending = (
      occs: typeof extractedData.hashOccurrences,
      artifactType: 'hash' | 'domain',
    ): PrevalenceScatterData['hashPoints'] =>
      occs.map((occ) => ({
        artifact: occ.artifact,
        artifactType,
        hostCount: 0,
        firstSeen: occ.eventTimestamp,
        lastSeen: occ.eventTimestamp,
        totalOccurrences: occ.occurrenceCount,
        isRare: false,
        prevalenceScore: 0,
        envFirstSeen: undefined,
        pending: true,
      }));
    return {
      hashPoints: toPending(extractedData.hashOccurrences, 'hash'),
      domainPoints: toPending(extractedData.domainOccurrences, 'domain'),
      rarityThreshold: 3,
    };
  }, [extractedData, isAssetMode]);

  // The picker window, as a numeric [start, end] (ms), or null if unusable.
  const pickerRange = useMemo<[number, number] | null>(() => {
    const range = plotRange ?? timeRange;
    if (range?.start && range?.end) {
      const start = new Date(range.start).getTime();
      const end = new Date(range.end).getTime();
      if (!isNaN(start) && !isNaN(end)) {
        return [start, end];
      }
    }
    return null;
  }, [plotRange, timeRange]);

  // NAN-1701: search-window duration (hours) — rarity auto-populates only when
  // this is small; larger windows are gated behind an explicit load.
  const searchWindowHours = useMemo(
    () => (pickerRange ? (pickerRange[1] - pickerRange[0]) / 3_600_000 : null),
    [pickerRange],
  );
  // True while a >RARITY_AUTO_MAX_HOURS window hasn't been explicitly loaded.
  const rarityGatedByWindow =
    !isAssetMode &&
    !rarityManualLoad &&
    searchWindowHours != null &&
    searchWindowHours > RARITY_AUTO_MAX_HOURS;

  // The actual extent of the histogram buckets (ms), or null if no data.
  const dataExtent = useMemo<[number, number] | null>(() => {
    if (timelineData.length === 0) return null;
    let min = Infinity;
    let max = -Infinity;
    for (const d of timelineData) {
      if (d.timestamp < min) min = d.timestamp;
      if (d.timestamp > max) max = d.timestamp;
    }
    return Number.isFinite(min) && Number.isFinite(max) ? [min, max] : null;
  }, [timelineData]);

  // Effective rendered window = the picker range UNIONED with the histogram
  // extent (NAN-1454). An in-query `earliest=`/`latest=` modifier widens the
  // window the backend actually queries beyond the time picker; the histogram
  // is computed over that broadened window (the backend zero-fills the whole
  // adjusted range), so without the union the numeric XAxis clips every bar
  // outside the picker domain and the timeline looks empty even though data
  // came back. A normal search keeps the histogram inside the picker, so the
  // union is a no-op and the chart renders exactly as before.
  const effectiveRange = useMemo<[number, number] | null>(() => {
    if (pickerRange && dataExtent) {
      return [
        Math.min(pickerRange[0], dataExtent[0]),
        Math.max(pickerRange[1], dataExtent[1]),
      ];
    }
    return pickerRange ?? dataExtent;
  }, [pickerRange, dataExtent]);

  // X-axis domain:
  // - In static mode (timechart results): use data range for proper visualization
  // - In normal mode: use the effective window so the chart spans the data
  const xDomain: [number, number] | ['dataMin', 'dataMax'] = useMemo(() => {
    // In static mode, use the actual data range
    if (staticMode) {
      return ['dataMin', 'dataMax'];
    }
    if (effectiveRange) {
      return timelinePlotDomain(chartType, pickerRange, effectiveRange)!;
    }
    return ['dataMin', 'dataMax'];
  }, [effectiveRange, staticMode, chartType, pickerRange]);

  // Check if time range spans multiple days (for showing dates in labels)
  const spansDays = useMemo(() => {
    // In static mode, derive from actual data range
    if (staticMode && timelineData.length >= 2) {
      const start = timelineData[0].timestamp;
      const end = timelineData[timelineData.length - 1].timestamp;
      return (end - start) > 24 * 60 * 60 * 1000;
    }
    if (effectiveRange) {
      return (effectiveRange[1] - effectiveRange[0]) > 24 * 60 * 60 * 1000; // > 24 hours
    }
    return false;
  }, [effectiveRange, staticMode, timelineData]);

  // Check time range duration for formatting precision
  const rangeDurationMs = useMemo(() => {
    // In static mode, derive from actual data range
    if (staticMode && timelineData.length >= 2) {
      const start = timelineData[0].timestamp;
      const end = timelineData[timelineData.length - 1].timestamp;
      return end - start || 24 * 60 * 60 * 1000;
    }
    if (effectiveRange) {
      return effectiveRange[1] - effectiveRange[0];
    }
    return 24 * 60 * 60 * 1000; // default 24h
  }, [effectiveRange, staticMode, timelineData]);

  // Generate evenly-spaced tick values for the X-axis
  const xAxisTicks = useMemo(() => {
    if (!Array.isArray(xDomain) || xDomain.length !== 2) return undefined;
    const [start, end] = xDomain;
    if (typeof start !== 'number' || typeof end !== 'number') return undefined;

    const range = end - start;
    const targetTickCount = 20; // Aim for ~20 ticks

    // Find a nice interval (round to nice time boundaries)
    const rawInterval = range / targetTickCount;

    // Nice intervals in milliseconds: from 1sec up to 24hr
    const niceIntervals = [
      1000,                // 1 sec
      2 * 1000,            // 2 sec
      5 * 1000,            // 5 sec
      10 * 1000,           // 10 sec
      15 * 1000,           // 15 sec
      30 * 1000,           // 30 sec
      60 * 1000,           // 1 min
      5 * 60 * 1000,       // 5 min
      10 * 60 * 1000,      // 10 min
      15 * 60 * 1000,      // 15 min
      30 * 60 * 1000,      // 30 min
      60 * 60 * 1000,      // 1 hr
      2 * 60 * 60 * 1000,  // 2 hr
      4 * 60 * 60 * 1000,  // 4 hr
      6 * 60 * 60 * 1000,  // 6 hr
      12 * 60 * 60 * 1000, // 12 hr
      24 * 60 * 60 * 1000, // 24 hr
    ];

    // Find the smallest nice interval >= rawInterval
    const interval = niceIntervals.find(i => i >= rawInterval) || niceIntervals[niceIntervals.length - 1];

    // Align start to the interval boundary
    const alignedStart = Math.ceil(start / interval) * interval;

    const ticks: number[] = [];
    for (let t = alignedStart; t <= end; t += interval) {
      ticks.push(t);
    }

    return ticks.length > 0 ? ticks : undefined;
  }, [xDomain]);

  const formatAxisLabel = useCallback((timestamp: number): string => {
    const date = new Date(timestamp);

    // Very tight range (< 2 min): show seconds.milliseconds
    if (rangeDurationMs < 2 * 60 * 1000) {
      return formatInTimeZone(date, 'UTC', 'HH:mm:ss.SSS');
    }

    // Tight range (< 30 min): show seconds
    if (rangeDurationMs < 30 * 60 * 1000) {
      return formatInTimeZone(date, 'UTC', 'HH:mm:ss');
    }

    // Multi-day range: show date + time
    if (spansDays) {
      return formatInTimeZone(date, 'UTC', 'M/d HH:mm');
    }

    // Default: just time
    return formatInTimeZone(date, 'UTC', 'HH:mm');
  }, [spansDays, rangeDurationMs]);

  // Calculate bucket interval for tooltip display
  const bucketInterval = useMemo(() => calculateBucketInterval(timelineData), [timelineData]);

  // Raw counts at the query edges; partial connections are dashed and faded.
  const plotData = useMemo<TimelinePlotPoint[]>(
    () =>
      buildTimelinePlotData(timelineData, {
        bucketMs: bucketInterval,
        domain: timelinePlotDomain(chartType, pickerRange, effectiveRange),
        window: pickerRange,
        chartType,
        staticMode,
      }),
    [timelineData, bucketInterval, effectiveRange, pickerRange, chartType, staticMode],
  );

  const seriesData = useMemo(
    () => staticMode ? plotData : timelineSeriesData(plotData, chartType, timelinePlotDomain(chartType, pickerRange, effectiveRange)),
    [plotData, chartType, pickerRange, effectiveRange, staticMode],
  );

  // Chart mouse events report the plotted point; Search.tsx's click / drag
  // zoom expects the bucket START, so translate before forwarding.
  const handleChartClick = useCallback(
    (e: unknown) => {
      const timestamp = resolveBucketStart(seriesData, e as Parameters<typeof resolveBucketStart>[1]);
      if (timestamp !== undefined) onTimelineClick({ activePayload: [{ payload: { timestamp } }] });
    },
    [onTimelineClick, seriesData],
  );
  const handleChartMouseDown = useCallback(
    (e: unknown) =>
      onMouseDown({ activeLabel: resolveBucketStart(seriesData, e as Parameters<typeof resolveBucketStart>[1]) }),
    [onMouseDown, seriesData],
  );
  const handleChartMouseMove = useCallback(
    (e: unknown) =>
      onMouseMove({ activeLabel: resolveBucketStart(seriesData, e as Parameters<typeof resolveBucketStart>[1]) }),
    [onMouseMove, seriesData],
  );

  // Drag highlight: refArea{Left,Right} are bucket starts — cover the whole
  // selected buckets (start of the earlier → end of the later), clamped.
  const refArea = useMemo<[number, number] | null>(() => {
    if (refAreaLeft == null || refAreaRight == null) return null;
    const a = Number(refAreaLeft);
    const b = Number(refAreaRight);
    if (!Number.isFinite(a) || !Number.isFinite(b)) return null;
    let x1 = Math.min(a, b);
    let x2 = Math.max(a, b) + bucketInterval;
    if (effectiveRange) {
      x1 = Math.max(x1, effectiveRange[0]);
      x2 = Math.min(x2, effectiveRange[1]);
    }
    return [x1, x2];
  }, [refAreaLeft, refAreaRight, bucketInterval, effectiveRange]);

  // Partial buckets have the same dots as the rest of the series.
  const renderLineDot = useCallback(
    (props: { cx?: number; cy?: number; index?: number; payload?: TimelinePlotPoint }) => {
      const { cx, cy, index, payload } = props;
      if (cx == null || cy == null || !payload) {
        return <g key={`dot-${index}`} />;
      }
      return (
        <circle
          key={`dot-${index}`}
          cx={cx}
          cy={cy}
          r={3}
          fill="var(--primary)"
          fillOpacity={payload.partial ? 0.5 : 1}
        />
      );
    },
    [],
  );

  // Format timestamp for tooltip (includes date if range spans days)
  const formatTooltipTime = useCallback((timestamp: number): string => {
    const date = new Date(timestamp);

    // Very tight range (< 2 min): show seconds.milliseconds
    if (rangeDurationMs < 2 * 60 * 1000) {
      return formatInTimeZone(date, 'UTC', 'HH:mm:ss.SSS');
    }

    // Tight range (< 30 min): show seconds
    if (rangeDurationMs < 30 * 60 * 1000) {
      return formatInTimeZone(date, 'UTC', 'HH:mm:ss');
    }

    // Multi-day range: always show date + time for clarity
    if (spansDays) {
      return formatInTimeZone(date, 'UTC', 'MMM d, HH:mm');
    }

    // Default: just time with seconds for precision
    return formatInTimeZone(date, 'UTC', 'HH:mm:ss');
  }, [spansDays, rangeDurationMs]);

  // Helper: build scatter points from per-event artifact occurrences.
  // One dot per event, positioned at the event's actual timestamp.
  const buildScatterPoints = useCallback((
    occurrences: ApiArtifactOccurrence[],
    prevalenceMap: Map<string, { hostCount: number; isRare: boolean; prevalenceScore: number; totalOccurrences: number; envFirstSeen?: Date; prevalenceSource?: PrevalenceSource; inWindowHosts?: number }>,
    artifactType: 'hash' | 'domain',
  ): PrevalenceScatterData['hashPoints'] => {
    return occurrences
      // An occurrence with no usable timestamp has no X position. Plotting it at
      // "now" (what the old parse fallback did) puts it at the right-hand edge
      // and reads as a fresh sighting; dropping it is the honest rendering.
      .filter((occ) => !Number.isNaN(parseTimestampAsUTC(occ.timestamp).getTime()))
      .map((occ) => {
        const prevalence = prevalenceMap.get(occ.artifact.toLowerCase());
        const eventTs = parseTimestampAsUTC(occ.timestamp);
        return {
          artifact: occ.artifact,
          artifactType,
          // NAN-1699: a prevalence miss is NOT a rare artifact — it means we have
          // no baseline for it (untracked, or agg lag), so don't fabricate
          // rare-on-1-host (that mislabeled ~157 common Windows binaries as rare).
          // host_count 0 / not-rare = "unbaselined"; the backend now returns real
          // counts for common artifacts so genuine misses are the exception.
          hostCount: prevalence?.hostCount ?? 0,
          firstSeen: eventTs,
          lastSeen: eventTs,
          totalOccurrences: 1,
          isRare: prevalence?.isRare ?? false,
          prevalenceScore: prevalence?.prevalenceScore ?? 0,
          // No event-time fallback: novelty ("new to env") must key off a REAL
          // env-first-seen, never the occurrence time (which is always "now").
          envFirstSeen: prevalence?.envFirstSeen,
          // NAN-2361: asset mode computes layer 1 SERVER-side (the rows are
          // already in hand there, so it costs no extra query) and sends the
          // provenance down. Absent = ClickHouse/UDM, where a real count is a
          // baseline and a zero is genuinely absent.
          prevalenceSource:
            prevalence?.prevalenceSource ??
            ((prevalence?.hostCount ?? 0) > 0 ? 'baseline' : 'none'),
          inWindowHosts: prevalence?.inWindowHosts,
          baselineHostCount:
            prevalence?.prevalenceSource === 'in-window' ? undefined : prevalence?.hostCount,
        };
      });
  }, []);

  // Fetch scatter data when panel is opened and artifacts change
  const loadScatterData = useCallback(async (maxHostCountOverride?: number) => {
    // NAN-2361: last-writer-wins guard.
    //
    // This loader is fired for the SLIM artifact set as soon as the page has
    // artifacts, and again when discovery lands with the complete set. Both
    // calls are long-running and both commit unconditionally, so whichever
    // resolves LAST won — and the slim run is the smaller query, but not
    // reliably the faster one (it can be queued behind the discovery fan-out at
    // the 5-per-user admission limit). When it lost the race it restored the
    // page-derived chart on top of discovery's, leaving the plotted dots out of
    // lockstep with `rarityTruncated` and the artifact-count banner.
    //
    // Every commit below is therefore gated on this run still being current.
    //
    // The generation is claimed only once a branch actually commits to
    // fetching — NOT at entry. Bumping on entry would let an invocation that
    // immediately returns on the dedup guard (or on `!hasArtifacts`) orphan a
    // genuinely in-flight run, which would then decline to clear the spinner
    // that nothing else is going to clear.
    let isStale = () => false;
    const beginRun = (key: string | null) => {
      const run = ++scatterRunRef.current;
      activeRunKeyRef.current = key;
      isStale = () => scatterRunRef.current !== run;
    };
    // Settle: only the current run may release the in-flight marker.
    const endRun = () => {
      if (!isStale()) activeRunKeyRef.current = null;
    };
    // "Already fetched" is a safe skip ONLY while nothing newer is in flight.
    //
    // Otherwise this sequence commits stale data: K0 completes, K1 starts (and
    // has already blanked the chart), then the inputs revert to K0. Comparing
    // against `lastFetchedKeyRef` alone made that third invocation return
    // immediately, leaving K1 the current run — so K1 passed its own staleness
    // check and painted its results over a UI whose inputs are K0. Falling
    // through instead supersedes K1 and refetches K0, which is a wasted query
    // in a rare case and the correct chart in every case.
    const canSkipAsAlreadyFetched = (key: string) =>
      key === lastFetchedKeyRef.current &&
      (activeRunKeyRef.current === null || activeRunKeyRef.current === key);
    // In asset mode, use the dedicated endpoint that does server-side prevalence filtering
    if (isAssetMode && assetContext && timeRange) {
      const effectiveMaxHostCount = maxHostCountOverride ?? assetMaxHostCount;
      const assetKey = JSON.stringify({
        asset: true,
        ...assetContext,
        timeRange,
        maxHostCount: effectiveMaxHostCount,
      });
      if (canSkipAsAlreadyFetched(assetKey)) return;

      beginRun(assetKey);
      setIsLoading(true);
      setError(null);

      try {
        // Single call: backend does summary → prevalence lookup → filter → per-event occurrences
        const response = await api.getAssetArtifacts({
          identifier_field: assetContext.identifier_field,
          identifier_value: assetContext.identifier_value,
          identities: assetContext.identities,
          time_range: timeRange,
          max_host_count: effectiveMaxHostCount,
        });

        // Build prevalence lookup maps from the included prevalence metadata
        // (prevalence is unfiltered — covers ALL artifacts for slider range)
        const hashPrevalenceMap = new Map<string, {
          hostCount: number; isRare: boolean; prevalenceScore: number;
          totalOccurrences: number; envFirstSeen?: Date;
          prevalenceSource?: PrevalenceSource; inWindowHosts?: number;
        }>();
        for (const p of response.hash_prevalence) {
          hashPrevalenceMap.set(p.artifact.toLowerCase(), {
            hostCount: p.host_count, isRare: p.is_rare,
            prevalenceScore: p.prevalence_score, totalOccurrences: p.total_occurrences,
            // REAL env-wide first-seen only. `p.first_seen` is the in-window
            // minimum — keying novelty off it stamped long-known artifacts
            // "new to env" whenever their first in-window hit was recent.
            envFirstSeen: p.env_first_seen ? parseTimestampAsUTC(p.env_first_seen) : undefined,
            // NAN-2361: computed server-side for asset mode; absent on the
            // ClickHouse/UDM path.
            prevalenceSource: p.prevalence_source,
            inWindowHosts: p.in_window_hosts,
          });
        }

        const domainPrevalenceMap = new Map<string, {
          hostCount: number; isRare: boolean; prevalenceScore: number;
          totalOccurrences: number; envFirstSeen?: Date;
          prevalenceSource?: PrevalenceSource; inWindowHosts?: number;
        }>();
        for (const p of response.domain_prevalence) {
          domainPrevalenceMap.set(p.artifact.toLowerCase(), {
            hostCount: p.host_count, isRare: p.is_rare,
            prevalenceScore: p.prevalence_score, totalOccurrences: p.total_occurrences,
            // REAL env-wide first-seen only — see the hash map above.
            envFirstSeen: p.env_first_seen ? parseTimestampAsUTC(p.env_first_seen) : undefined,
            // NAN-2361: computed server-side for asset mode; absent on the
            // ClickHouse/UDM path.
            prevalenceSource: p.prevalence_source,
            inWindowHosts: p.in_window_hosts,
          });
        }

        // Build scatter points — one dot per event at its actual timestamp
        // (occurrences are filtered by max_host_count, may be empty)
        const hashPoints = buildScatterPoints(response.hashes, hashPrevalenceMap, 'hash');
        const domainPoints = buildScatterPoints(response.domains, domainPrevalenceMap, 'domain');

        // Compute max host count from ALL prevalence data (unfiltered) for slider range
        const allHostCounts = [
          ...response.hash_prevalence.map(p => p.host_count),
          ...response.domain_prevalence.map(p => p.host_count),
        ];
        const maxArtifactHostCount = allHostCounts.length > 0 ? Math.max(...allHostCounts) : undefined;
        // Prefer the backend's pre-LIMIT total: the prevalence arrays are
        // capped at 50 per class, so their lengths under-count on busy assets.
        const totalUnfilteredArtifacts = response.total_artifacts
          ?? (response.hash_prevalence.length + response.domain_prevalence.length);

        if (isStale()) return;
        setScatterData({
          hashPoints,
          domainPoints,
          rarityThreshold: response.rarity_threshold,
          maxArtifactHostCount,
          totalUnfilteredArtifacts: totalUnfilteredArtifacts > 0 ? totalUnfilteredArtifacts : undefined,
        });
        lastFetchedKeyRef.current = assetKey;
      } catch (err) {
        if (isStale()) return;
        setError(err instanceof Error ? err.message : 'Failed to load prevalence data');
        lastFetchedKeyRef.current = null;
      } finally {
        // A superseded run must not clear the spinner the CURRENT run is still
        // showing, nor leave it stuck when it is itself the current run.
        if (!isStale()) setIsLoading(false);
        endRun();
      }
      return;
    }

    // Non-asset mode: use artifacts extracted from search results
    if (!hasArtifacts) {
      // Supersede any in-flight run: "this query has no artifacts" is a final
      // answer, and letting an older fetch land afterwards would repopulate the
      // chart from a superseded artifact set. Clear the spinner here since the
      // orphaned run will now decline to.
      beginRun(null);
      setScatterData(null);
      setIsLoading(false);
      activeRunKeyRef.current = null;
      return;
    }

    // Dedup: skip if we already fetched for this exact artifact set + window.
    // (NAN-1700: window MUST be in the key — the request is windowed, so a window
    // change with the same artifacts would otherwise be skipped and show stale
    // rarity.)
    const currentKey = JSON.stringify({
      hashes: extractedData.hashes,
      domains: extractedData.domains,
      window: timeWindow,
    });
    if (canSkipAsAlreadyFetched(currentKey)) {
      return;
    }

    // NAN-1700: new artifact set/window — drop the previous (now stale) enriched
    // data so the pending points render immediately for THIS search instead of
    // the old dots lingering until the new fetch lands.
    beginRun(currentKey);
    setScatterData(null);
    setIsLoading(true);
    setError(null);

    try {
      // NAN-1701: batch the prevalence lookup into MAX_BULK-sized chunks so the
      // full (already ceiling-capped, at extraction) artifact set gets complete
      // coverage — an analyst must see every artifact, not the first 50. Combine
      // hashes + domains, chunk to the 100/request limit, fetch with a bounded
      // concurrency pool, and merge.
      const tagged: Array<['hash' | 'domain', string]> = [
        ...extractedData.hashes.map((h) => ['hash', h] as ['hash', string]),
        ...extractedData.domains.map((d) => ['domain', d] as ['domain', string]),
      ];
      const chunks: Array<Array<['hash' | 'domain', string]>> = [];
      for (let i = 0; i < tagged.length; i += RARITY_BATCH_SIZE) chunks.push(tagged.slice(i, i + RARITY_BATCH_SIZE));

      const chunkResponses = await mapLimit(chunks, RARITY_MAX_CONCURRENT, (chunk) =>
        fetchScatterDataRef.current({
          artifacts: {
            hashes: chunk.filter(([t]) => t === 'hash').map(([, v]) => v),
            domains: chunk.filter(([t]) => t === 'domain').map(([, v]) => v),
            ips: [],
          },
          window: timeWindow,
        }),
      );
      const response = {
        hash_points: chunkResponses.flatMap((r) => r.hash_points),
        domain_points: chunkResponses.flatMap((r) => r.domain_points),
        rarity_threshold: chunkResponses[0]?.rarity_threshold ?? 3,
      };

      // Build lookup maps for prevalence data (host_count, is_rare, env first_seen, etc.)
      const hashPrevalenceMap = new Map<string, {
        hostCount: number;
        isRare: boolean;
        prevalenceScore: number;
        totalOccurrences: number;
        envFirstSeen: Date;
      }>();
      for (const p of response.hash_points) {
        hashPrevalenceMap.set(p.artifact.toLowerCase(), {
          hostCount: p.host_count,
          isRare: p.is_rare,
          prevalenceScore: p.prevalence_score,
          totalOccurrences: p.total_occurrences,
          envFirstSeen: new Date(p.first_seen),
        });
      }

      const domainPrevalenceMap = new Map<string, {
        hostCount: number;
        isRare: boolean;
        prevalenceScore: number;
        totalOccurrences: number;
        envFirstSeen: Date;
      }>();
      for (const p of response.domain_points) {
        domainPrevalenceMap.set(p.artifact.toLowerCase(), {
          hostCount: p.host_count,
          isRare: p.is_rare,
          prevalenceScore: p.prevalence_score,
          totalOccurrences: p.total_occurrences,
          envFirstSeen: new Date(p.first_seen),
        });
      }

      // NAN-2361 layer 1: ask the events we already matched how many hosts
      // touched each artifact IN THIS WINDOW. The baseline snapshot lags ingest
      // by 30-90 min, so for a minutes-old alert it simply has nothing — and a
      // miss used to arrive as host_count 0, rendered as "boring".
      //
      // This does NOT replace the baseline. Environment prevalence is a
      // question about history: an asset that touched the artifact yesterday is
      // outside the search window and invisible here. So layer 1 is only ever
      // the fallback when the baseline has nothing, and is labelled as a
      // window-scoped lower bound when used.
      //
      // Skipped entirely for ClickHouse/UDM tenants: those rows carry no
      // `enrichments`, so the stamp map is empty and we never issue the queries.
      // `rarityRows` are `SearchResult`-shaped (`{id, timestamp, source, fields}`),
      // not raw OCSF rows -- `enrichments` lives at `.fields.enrichments`, one
      // level down. Passing the wrapper itself left every row's `enrichments`
      // undefined, so `lakeShaped` was permanently false and the whole in-window
      // layer silently never ran on the search page (asset mode is unaffected;
      // it builds its rows differently).
      const rowsForStamps = rarityRows.map(
        (r) => (r as unknown as { fields?: Record<string, unknown> }).fields ?? {},
      );
      const ingestStamps: Map<string, IngestStamp> = harvestIngestStamps(
        rowsForStamps,
        (row) => {
          const raw = (row as { timestamp?: unknown }).timestamp ?? (row as { time?: unknown }).time;
          if (raw == null) return null;
          if (typeof raw === 'number') return Number.isFinite(raw) ? raw : null;
          // Lake rows carry `time` as a NAIVE string ("2026-08-21 12:28:28.109000",
          // no zone). A bare Date.parse reads that as LOCAL time, shifting
          // `earliestMs` by the viewer's UTC offset while the occurrence
          // timestamps it's compared against are parsed as UTC — west of UTC
          // every occurrence passed the earliest-pin check (novelty ring on
          // every dot), east of UTC none did (ring suppressed entirely).
          const parsed = parseTimestampAsUTC(String(raw)).getTime();
          return Number.isFinite(parsed) ? parsed : null;
        },
      );
      const lakeShaped = ingestStamps.size > 0;

      let hashObservations = new Map<string, InWindowObservation>();
      let domainObservations = new Map<string, InWindowObservation>();
      // Mirrors `extractedData`'s source precedence exactly: whenever discovery
      // supplied the artifact list, it must also supply their observations, or
      // the two fall out of lockstep and artifacts render with another source's
      // host counts.
      if (discoveryResult) {
        // Discovery (above) already ran the unbounded `stats ... by <path>`
        // aggregate to build the artifact list in the first place, so it
        // already carries hosts/events/first_in_window per artifact -- no
        // second per-artifact lookup round trip needed here.
        hashObservations = discoveryResult.hash.observations;
        domainObservations = discoveryResult.domain.observations;
      } else if (lakeShaped && timeRange?.start && timeRange?.end) {
        // slim mode: artifacts came from already-loaded `results`, not
        // discovery, so their in-window stats still need a lookup.
        const runObservations = async (artifacts: string[], paths: readonly string[]) => {
          const queries = buildObservationQueries(artifacts, paths);
          if (queries.length === 0) return new Map<string, InWindowObservation>();
          // SEARCH_MAX_CONCURRENT + retry: same 5-concurrent admission limit as
          // discovery — a pool of 6 could 429 its own sixth query.
          const responses = await mapLimit(queries, SEARCH_MAX_CONCURRENT, async (q) => {
            try {
              const resp = await searchWithRetry({
                query: q.npl,
                time_range: timeRange!,
                // `limit` caps GROUPS, not events — must clear the chunk size or
                // artifacts silently drop out of the aggregate.
                limit: Math.max(OBSERVATION_LIMIT, q.artifacts.length * 2),
                skip_histogram: true,
              });
              return (resp.results ?? []).map((row) => ({
                path: q.path,
                row: row as unknown as Record<string, unknown>,
              }));
            } catch {
              // Layer 1 is an enhancement; a failed aggregate must degrade to
              // "no in-window data", never break the chart.
              return [];
            }
          });
          return mergeObservations(artifacts, responses.flat());
        };
        [hashObservations, domainObservations] = await Promise.all([
          runObservations(extractedData.hashes, HASH_PATHS),
          runObservations(extractedData.domains, DOMAIN_PATHS),
        ]);
      }

      // Merge per-event timestamps (from extractedData) with environment-wide
      // prevalence stats (from API). X-axis prefers the in-window observation's
      // `firstInWindow` (unbounded aggregate) over the raw occurrence timestamp,
      // which is truncated to whatever page the search loaded and collapses to
      // the tail of the window once event volume exceeds the page size.
      const hashPoints: PrevalenceScatterData['hashPoints'] = extractedData.hashOccurrences
        .map((occ) =>
          buildPoint(
            occ,
            'hash',
            hashPrevalenceMap.get(occ.artifact),
            hashObservations.get(occ.artifact),
            ingestStamps.get(occ.artifact),
            response.rarity_threshold,
          ),
        );

      const domainPoints: PrevalenceScatterData['domainPoints'] = extractedData.domainOccurrences
        .map((occ) =>
          buildPoint(
            occ,
            'domain',
            domainPrevalenceMap.get(occ.artifact),
            domainObservations.get(occ.artifact),
            ingestStamps.get(occ.artifact),
            response.rarity_threshold,
          ),
        );

      if (isStale()) return;
      setScatterData({
        hashPoints,
        domainPoints,
        rarityThreshold: response.rarity_threshold,
      });
      lastFetchedKeyRef.current = currentKey;
    } catch (err) {
      if (isStale()) return;
      setError(err instanceof Error ? err.message : 'Failed to load prevalence data');
      // NAN-1700: DON'T mark the key as fetched on failure, or the Retry button
      // (and a later re-open) hit the dedup guard and can never recover — mirror
      // the asset path which nulls it. More visible now that prefetch can fail in
      // the background before the analyst ever opens Rarity.
      lastFetchedKeyRef.current = null;
      setMode('timeline');
    } finally {
      // See the asset branch: only the current run owns the spinner.
      if (!isStale()) setIsLoading(false);
      endRun();
    }
  // Note: fetchScatterData accessed via stable ref (fetchScatterDataRef) to avoid
  // cascading identity changes from useMutation on every render
  // `rarityRows` is included because NAN-2361's stamp harvest reads it; it is
  // memoized from the same inputs as `extractedData`, so it changes in lockstep
  // rather than adding a new invalidation source.
  }, [extractedData, rarityRows, hasArtifacts, timeWindow, isAssetMode, assetContext, timeRange, buildScatterPoints, assetMaxHostCount, discoveryResult, slimHasArtifacts]);

  // NAN-1700: PREFETCH prevalence as soon as a search yields artifacts — not
  // gated on the Rarity tab being open. The agg lookup can take a while, so
  // firing it non-blocking (fire-and-forget; results render independently) means
  // the scatter is already warm by the time the analyst switches to it, instead
  // of making them wait then. `loadScatterData`'s lastFetchedKeyRef dedups, so
  // this runs once per unique artifact-set/window. Still skip when the whole
  // timeline card is collapsed (nothing to warm for a hidden card).
  useEffect(() => {
    if (collapsed) return;
    // In asset mode, load when assetContext is available (artifacts come from backend)
    if (isAssetMode && assetContext) {
      loadScatterData();
    } else if (!isAssetMode && hasArtifacts) {
      // NAN-1701: don't auto-load rarity for large search windows — wait for the
      // explicit "Load rarity" click (rarityGatedByWindow).
      if (rarityGatedByWindow) return;
      loadScatterData();
    }
  }, [hasArtifacts, collapsed, loadScatterData, isAssetMode, assetContext, rarityGatedByWindow]);

  // NAN-1701: a new search / window resets the explicit-load opt-in, so a fresh
  // large-window search re-prompts instead of silently reusing the prior consent.
  useEffect(() => {
    setRarityManualLoad(false);
  }, [extractedData]);

  const handleArtifactClick = useCallback((artifact: string, artifactType: 'hash' | 'domain', timestamp?: Date) => {
    if (onArtifactFilter) onArtifactFilter(artifact, artifactType, timestamp);
    // In asset mode, stay on prevalence view (scrolling happens in AssetView)
    if (!isAssetMode) {
      setMode('timeline');
    }
  }, [onArtifactFilter, isAssetMode]);

  // In asset mode, slider changes trigger a server-side re-fetch
  // (debouncing is handled at the PrevalenceScatterPlot component level)
  const handleMaxHostCountChange = useCallback((newMax: number) => {
    if (!isAssetMode) return;
    setAssetMaxHostCount(newMax);
    lastFetchedKeyRef.current = null; // Force re-fetch
    loadScatterData(newMax);
  }, [isAssetMode, loadScatterData]);

  const handleSelectionChange = useCallback((selectedArtifacts: string[]) => {
    if (onSelectionFilter) onSelectionFilter(selectedArtifacts);
  }, [onSelectionFilter]);

  const rareCount = useMemo(() => {
    if (!scatterData) return 0;
    return scatterData.hashPoints.filter((p) => p.isRare).length + scatterData.domainPoints.filter((p) => p.isRare).length;
  }, [scatterData]);

  return (
    <Card className="search-workspace-section bg-card border border-border rounded-lg">
      <CardContent className={collapsed ? "p-2.5 px-3.5" : "px-3.5 pt-2.5 pb-3"}>
        <div className="flex flex-wrap items-center justify-between gap-2 font-mono text-[10.5px] tracking-[0.12em] uppercase text-muted-foreground font-semibold">
          <div className="flex items-center gap-2 cursor-pointer min-w-0" onClick={onToggleCollapsed}>
            <div className="flex items-center gap-1.5 text-primary min-w-0">
              {mode === 'timeline' ? <LineChartIcon className="w-[12px] h-[12px] shrink-0"/> : <Fingerprint className="w-[12px] h-[12px] shrink-0"/>}
              <span className="truncate">{title || (mode === 'timeline' ? 'Event Stream' : 'Artifact Rarity')}</span>
              {!collapsed && mode === 'timeline' && !staticMode && (
                <span className="text-muted-foreground/50 font-medium normal-case tracking-[0.02em] ml-1.5 hidden md:inline truncate">
                  drag to zoom · bucket {formatBucketLabel(timelineData)}
                </span>
              )}
              {!collapsed && mode === 'prevalence' && scatterData && (
                <span className="text-muted-foreground/50 font-medium normal-case tracking-[0.02em] ml-1.5 hidden md:inline truncate">
                  prevalence across {(scatterData.hashPoints.length + scatterData.domainPoints.length).toLocaleString()} artifacts
                </span>
              )}
            </div>
            {mode === 'prevalence' && scatterData && (
              <Badge variant="outline" className="border-border text-muted-foreground text-[9.5px] tracking-[0.08em] font-medium h-[18px] px-1.5 py-0 ml-2">
                {scatterData.hashPoints.length + scatterData.domainPoints.length} artifacts
              </Badge>
            )}
            {mode === 'prevalence' && rareCount > 0 && (
              <Badge variant="outline" className="bg-red-500/15 text-red-400 border-red-500/30 text-[9.5px] tracking-[0.08em] font-medium h-[18px] px-1.5 py-0">
                <AlertTriangle className="w-2.5 h-2.5 mr-1" />{rareCount} rare
              </Badge>
            )}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {/* Chart type (bars/line/area) — compact icon toggle; only when
                stream mode is active + card expanded. Matches mockup's
                `streamMode` 2-button toggle, extended to 3 options. */}
            {!collapsed && mode === 'timeline' && (
              <div className="inline-flex items-center rounded-md border border-border bg-foreground/[0.03] p-0.5">
                <button
                  onClick={(e) => { e.stopPropagation(); onChartTypeChange('bar'); }}
                  aria-label="Bar chart"
                  className={cn(
                    'w-6 h-[22px] flex items-center justify-center rounded-sm transition-colors',
                    chartType === 'bar'
                      ? 'bg-primary/10 text-primary'
                      : 'text-muted-foreground hover:text-foreground'
                  )}
                >
                  <ChartColumn className="w-[11px] h-[11px]" />
                </button>
                <button
                  onClick={(e) => { e.stopPropagation(); onChartTypeChange('line'); }}
                  aria-label="Line chart"
                  className={cn(
                    'w-6 h-[22px] flex items-center justify-center rounded-sm transition-colors',
                    chartType === 'line'
                      ? 'bg-primary/10 text-primary'
                      : 'text-muted-foreground hover:text-foreground'
                  )}
                >
                  <TrendingUp className="w-[11px] h-[11px]" />
                </button>
                <button
                  onClick={(e) => { e.stopPropagation(); onChartTypeChange('area'); }}
                  aria-label="Area chart"
                  className={cn(
                    'w-6 h-[22px] flex items-center justify-center rounded-sm transition-colors',
                    chartType === 'area'
                      ? 'bg-primary/10 text-primary'
                      : 'text-muted-foreground hover:text-foreground'
                  )}
                >
                  <Activity className="w-[11px] h-[11px]" />
                </button>
              </div>
            )}
            {/* Stream/Rarity tabs — shadcn Tabs with mockup overrides.
                Hidden in static mode; disabled Rarity when no artifacts. */}
            {!staticMode && (
              <Tabs
                value={mode === 'timeline' ? 'stream' : 'rarity'}
                // NAN-1689: Rarity is available whenever a search has run — opening
                // it fetches full-field artifacts on demand (the slim table_view
                // rows can't be relied on to carry hashes/domains).
                onValueChange={(v) => setMode(v === 'stream' ? 'timeline' : 'prevalence')}
                onClick={(e) => e.stopPropagation()}
              >
                <TabsList className="h-auto rounded-md p-0.5 bg-foreground/[0.03] border border-border gap-0">
                  <TabsTrigger
                    value="stream"
                    className="h-auto rounded-sm py-0.5 px-2.5 text-[10.5px] tracking-[0.06em] gap-1.5 font-medium normal-case data-[state=active]:bg-primary/10 data-[state=active]:text-primary data-[state=inactive]:text-muted-foreground hover:text-foreground data-[state=active]:hover:text-primary"
                  >
                    <ChartColumn className="w-[11px] h-[11px]" />
                    <span className="hidden md:inline">Event Stream</span>
                  </TabsTrigger>
                  <TabsTrigger
                    value="rarity"
                    disabled={!hasSearched && !isAssetMode}
                    title={
                      artifactFetchLoading || discoveryLoading
                        ? 'Finding artifacts…'
                        : !hasSearched && !isAssetMode
                          ? 'Run a search to see artifact rarity'
                          : 'Artifact Rarity'
                    }
                    className="h-auto rounded-sm py-0.5 px-2.5 text-[10.5px] tracking-[0.06em] gap-1.5 font-medium normal-case data-[state=active]:bg-primary/10 data-[state=active]:text-primary data-[state=inactive]:text-muted-foreground hover:text-foreground data-[state=active]:hover:text-primary"
                  >
                    <Fingerprint className="w-[11px] h-[11px]" />
                    <span className="hidden md:inline">Rarity</span>
                  </TabsTrigger>
                </TabsList>
              </Tabs>
            )}
            {/* Zoom controls — stream mode + expanded + interactive. Mockup
                doesn't show these but they're existing Search functionality. */}
            {!collapsed && mode === 'timeline' && !staticMode && (
              <div className="flex items-center gap-0.5">
                <button onClick={(e) => { e.stopPropagation(); onZoomIn(); }} className="p-1 rounded-sm transition-colors text-muted-foreground hover:text-foreground hover:bg-foreground/5" title="Zoom in"><ZoomIn className="w-[11px] h-[11px]" /></button>
                <button onClick={(e) => { e.stopPropagation(); onZoomOut(); }} className="p-1 rounded-sm transition-colors text-muted-foreground hover:text-foreground hover:bg-foreground/5" title="Zoom out"><ZoomOut className="w-[11px] h-[11px]" /></button>
                <button onClick={(e) => { e.stopPropagation(); onResetZoom(); }} className="p-1 rounded-sm transition-colors text-muted-foreground hover:text-foreground hover:bg-foreground/5" title="Reset"><RotateCcw className="w-[11px] h-[11px]" /></button>
              </div>
            )}
            {mode === 'prevalence' && isLoading && <LoadingIcon className="w-3.5 h-3.5 text-muted-foreground" />}
            {isAssetMode && assetFilterActive && onClearAssetFilter && (
              <button
                onClick={(e) => { e.stopPropagation(); onClearAssetFilter(); }}
                className="flex items-center gap-1 px-2 py-1 text-xs rounded-md bg-primary/10 text-primary hover:bg-primary/20 transition-colors"
              >
                <X className="w-3 h-3" />
                Clear scope
              </button>
            )}
            {/* Count label — mockup pattern: `<b>N</b> events` inline mono.
                Shows "events" for timeline, "unique" for rarity. */}
            <span className="font-mono text-[11px] tracking-wide font-medium text-muted-foreground normal-case ml-1">
              <b className="text-foreground font-semibold tabular-nums">
                {mode === 'timeline'
                  ? eventCount.toLocaleString()
                  : scatterData ? scatterData.hashPoints.length + scatterData.domainPoints.length : 0}
              </b>{' '}
              {mode === 'timeline' ? 'events' : 'unique'}
            </span>
          </div>
        </div>
        {!collapsed && (
          <div className="mt-4">
            {mode === 'timeline' ? (
              <div className="select-none" style={{ userSelect: 'none' }} tabIndex={-1}>
                {eventCount > 0 && resultCount !== undefined && resultCount < eventCount && (
                  <p className="text-xs font-mono text-muted-foreground mb-2 flex items-center gap-1">
                    <AlertTriangle className="w-3 h-3" />Stream sees {eventCount.toLocaleString()} hits; table returned {resultCount.toLocaleString()} rows
                  </p>
                )}
                {/* hl-chart: scoped target for the search-complete reveal
                    sweep (index.css, gated by .hl-wipe on the page root) */}
                <div className="hl-chart relative">
                <ResponsiveContainer width="100%" height={180}>
                  {chartType === 'bar' ? (
                    <BarChart
                      data={plotData}
                      barCategoryGap={0}
                      onClick={staticMode ? undefined : handleChartClick}
                      onMouseDown={staticMode ? undefined : handleChartMouseDown}
                      onMouseMove={staticMode ? undefined : handleChartMouseMove}
                      onMouseUp={staticMode ? undefined : onMouseUp}
                      onMouseLeave={staticMode ? undefined : onMouseUp}
                      style={{ cursor: staticMode ? 'default' : 'crosshair' }}
                    >
                      <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" vertical={false} />
                      <XAxis dataKey="x" type="number" domain={xDomain} ticks={xAxisTicks} tickFormatter={formatAxisLabel} stroke={CHART_AXIS_LINE} fontSize={10} tickLine={false} axisLine={false} minTickGap={50} tick={{ fill: CHART_AXIS_TEXT }} allowDataOverflow={true} />
                      <YAxis stroke={CHART_AXIS_LINE} fontSize={10} tickLine={false} axisLine={false} width={55} tickFormatter={formatYAxisTick} tick={{ fill: CHART_AXIS_TEXT }} />
                      <Tooltip content={<HistogramTooltip bucketInterval={bucketInterval} formatTime={formatTooltipTime} />} cursor={{ fill: 'rgba(255,255,255,0.05)' }} />
                      <Bar dataKey="events" fill="var(--primary)" radius={0} minPointSize={2} />
                      {plotData.filter(p => p.partialSpan).map(p => (
                        <ReferenceArea key={p.timestamp} x1={p.partialSpan![0]} x2={p.partialSpan![1]} strokeOpacity={0} fill="var(--primary)" fillOpacity={0.06} />
                      ))}
                      {!staticMode && refArea && <ReferenceArea x1={refArea[0]} x2={refArea[1]} strokeOpacity={0.3} fill="var(--primary)" fillOpacity={0.2} />}
                    </BarChart>
                  ) : chartType === 'line' ? (
                    <LineChart
                      data={seriesData}
                      onClick={staticMode ? undefined : handleChartClick}
                      onMouseDown={staticMode ? undefined : handleChartMouseDown}
                      onMouseMove={staticMode ? undefined : handleChartMouseMove}
                      onMouseUp={staticMode ? undefined : onMouseUp}
                      onMouseLeave={staticMode ? undefined : onMouseUp}
                      style={{ cursor: staticMode ? 'default' : 'crosshair' }}
                    >
                      <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" vertical={false} />
                      <XAxis dataKey="x" type="number" domain={xDomain} ticks={xAxisTicks} tickFormatter={formatAxisLabel} stroke={CHART_AXIS_LINE} fontSize={10} tickLine={false} axisLine={false} minTickGap={30} tick={{ fill: CHART_AXIS_TEXT }} allowDataOverflow={true} />
                      <YAxis stroke={CHART_AXIS_LINE} fontSize={10} tickLine={false} axisLine={false} width={55} tickFormatter={formatYAxisTick} tick={{ fill: CHART_AXIS_TEXT }} />
                      <Tooltip content={<HistogramTooltip bucketInterval={bucketInterval} formatTime={formatTooltipTime} />} />
                      <Line type="linear" dataKey="solid" stroke="var(--primary)" strokeWidth={2} dot={renderLineDot} activeDot={{ fill: 'var(--primary)', strokeWidth: 0, r: 5 }} />
                      <Line type="linear" dataKey="leadingPartial" stroke="var(--primary)" strokeOpacity={0.5} strokeDasharray="3 3" strokeWidth={2} dot={renderLineDot} activeDot={{ fill: 'var(--primary)', strokeWidth: 0, r: 5 }} />
                      <Line type="linear" dataKey="trailingPartial" stroke="var(--primary)" strokeOpacity={0.5} strokeDasharray="3 3" strokeWidth={2} dot={renderLineDot} activeDot={{ fill: 'var(--primary)', strokeWidth: 0, r: 5 }} />
                      {!staticMode && refArea && <ReferenceArea x1={refArea[0]} x2={refArea[1]} strokeOpacity={0.3} fill="var(--primary)" fillOpacity={0.2} />}
                    </LineChart>
                  ) : (
                    <AreaChart
                      data={seriesData}
                      onClick={staticMode ? undefined : handleChartClick}
                      onMouseDown={staticMode ? undefined : handleChartMouseDown}
                      onMouseMove={staticMode ? undefined : handleChartMouseMove}
                      onMouseUp={staticMode ? undefined : onMouseUp}
                      onMouseLeave={staticMode ? undefined : onMouseUp}
                      style={{ cursor: staticMode ? 'default' : 'crosshair' }}
                    >
                      <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" vertical={false} />
                      <XAxis dataKey="x" type="number" domain={xDomain} ticks={xAxisTicks} tickFormatter={formatAxisLabel} stroke={CHART_AXIS_LINE} fontSize={10} tickLine={false} axisLine={false} minTickGap={30} tick={{ fill: CHART_AXIS_TEXT }} allowDataOverflow={true} />
                      <YAxis stroke={CHART_AXIS_LINE} fontSize={10} tickLine={false} axisLine={false} width={55} tickFormatter={formatYAxisTick} tick={{ fill: CHART_AXIS_TEXT }} />
                      <Tooltip content={<HistogramTooltip bucketInterval={bucketInterval} formatTime={formatTooltipTime} />} />
                      <Area type="linear" dataKey="solid" stroke="var(--primary)" strokeWidth={2} fill="var(--primary)" fillOpacity={0.2} />
                      <Area type="linear" dataKey="leadingPartial" stroke="var(--primary)" strokeWidth={2} strokeOpacity={0.5} strokeDasharray="3 3" fill="var(--primary)" fillOpacity={0.07} />
                      <Area type="linear" dataKey="trailingPartial" stroke="var(--primary)" strokeWidth={2} strokeOpacity={0.5} strokeDasharray="3 3" fill="var(--primary)" fillOpacity={0.07} />
                      {!staticMode && refArea && <ReferenceArea x1={refArea[0]} x2={refArea[1]} strokeOpacity={0.3} fill="var(--primary)" fillOpacity={0.2} />}
                    </AreaChart>
                  )}
                </ResponsiveContainer>
                </div>
              </div>
            ) : (
              <div>
                {error ? (
                  <div className="flex items-center justify-center py-8 text-red-400 text-sm">
                    <AlertTriangle className="w-4 h-4 mr-2" />{error}
                    <Button variant="ghost" size="sm" onClick={() => loadScatterData()} className="ml-4 text-muted-foreground hover:text-primary"><RefreshCw className="w-3 h-3" />Retry query</Button>
                  </div>
                ) : rarityGatedByWindow ? (
                  // NAN-1701: large window — don't auto-score; require an explicit
                  // load. Gate on rarityGatedByWindow alone (not `&& !scatterData`)
                  // so a prior small-window search's stale dots don't linger here.
                  <div className="flex flex-col items-center justify-center py-8 gap-2 text-center px-4">
                    <div className="text-muted-foreground text-sm">Rarity auto-loads for windows ≤ {RARITY_AUTO_MAX_HOURS}h</div>
                    <div className="text-muted-foreground/70 text-xs max-w-md">
                      This search spans {searchWindowHours != null ? (searchWindowHours >= 24 ? `${Math.round(searchWindowHours / 24)}d` : `${Math.round(searchWindowHours)}h`) : ''} — prevalence is a small-window tool, and scoring every artifact over a wide window is heavier.
                    </div>
                    {/* Only flip the opt-in flag — the prefetch effect (which depends
                        on rarityGatedByWindow) fires the single load, so we don't
                        double-fetch by also calling loadScatterData() here. */}
                    <Button variant="outline" size="sm" onClick={() => setRarityManualLoad(true)} className="mt-1"><Fingerprint className="w-3 h-3" />Load rarity anyway</Button>
                  </div>
                ) : (scatterData ?? pendingScatterData) ? (
                  // NAN-1700: render immediately with pending points (event-time
                  // positions) and let the enriched scatterData animate the rarity
                  // in when it lands — no full-panel spinner blocking the view.
                  <>
                    {rarityTruncated && (
                      <div className="text-[10px] text-amber-400/80 text-center pb-1 flex items-center justify-center gap-2">
                        <span>
                          artifact discovery capped at {(discoveryLoadAll ? DISCOVERY_LIMIT_FULL : DISCOVERY_LIMIT).toLocaleString()} — {rarityTotalArtifacts.toLocaleString()} artifact matches across all paths (an artifact seen on several paths counts once per path)
                        </span>
                        {!discoveryLoadAll && (
                          <button
                            type="button"
                            className="underline underline-offset-2 hover:text-amber-300 disabled:opacity-50"
                            disabled={discoveryLoading}
                            onClick={() => setDiscoveryLoadAllKey(artifactFetchKey)}
                          >
                            load all (slower)
                          </button>
                        )}
                      </div>
                    )}
                    {discoveryFailedPaths.length > 0 && (
                      <div className="text-[10px] text-amber-400/80 text-center pb-1 flex items-center justify-center gap-2">
                        <span>
                          {discoveryFailedPaths.length} of {HASH_PATHS.length + DOMAIN_PATHS.length} artifact discovery queries failed — the chart may be missing artifacts
                        </span>
                        <button
                          type="button"
                          className="underline underline-offset-2 hover:text-amber-300 disabled:opacity-50"
                          disabled={discoveryLoading}
                          onClick={() => {
                            discoveryKeyRef.current = null;
                            setDiscoveryRetryNonce((n) => n + 1);
                          }}
                        >
                          retry
                        </button>
                      </div>
                    )}
                    {extractedData.droppedCount > 0 && (
                      <div className="text-[10px] text-amber-400/80 text-center pb-1">
                        showing first {RARITY_MAX_ARTIFACTS.toLocaleString()} of {(RARITY_MAX_ARTIFACTS + extractedData.droppedCount).toLocaleString()} artifacts — narrow the window to score the rest
                      </div>
                    )}
                    <PrevalenceScatterPlot data={(scatterData ?? pendingScatterData)!} onArtifactClick={handleArtifactClick} onSelectionChange={handleSelectionChange} height={180} loading={isLoading} timeRange={timeRange} onMaxHostCountChange={isAssetMode ? handleMaxHostCountChange : undefined} />
                  </>
                ) : (isLoading || artifactFetchLoading || discoveryLoading) ? (
                  <div className="flex items-center justify-center py-8 text-muted-foreground text-sm"><LoadingIcon className="w-4 h-4 mr-2" />Loading rarity index...</div>
                ) : (
                  // Total-failure case: every discovery path failed, so there are
                  // no dots to hang the incomplete-data banner on — say why the
                  // chart is empty rather than presenting a failure as "no data".
                  <div className="flex flex-col items-center justify-center py-8 gap-1.5 text-muted-foreground text-sm">
                    <span>No rarity data available</span>
                    {discoveryFailedPaths.length > 0 && (
                      <span className="text-[10px] text-amber-400/80 flex items-center gap-2">
                        {discoveryFailedPaths.length} of {HASH_PATHS.length + DOMAIN_PATHS.length} artifact discovery queries failed
                        <button
                          type="button"
                          className="underline underline-offset-2 hover:text-amber-300"
                          onClick={() => {
                            discoveryKeyRef.current = null;
                            setDiscoveryRetryNonce((n) => n + 1);
                          }}
                        >
                          retry
                        </button>
                      </span>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
