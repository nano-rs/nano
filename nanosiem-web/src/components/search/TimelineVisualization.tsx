// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState, useEffect, useMemo, useCallback, useRef } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { cn } from '@/lib/utils';
import {
  ChartColumn,
  TrendingUp,
  Activity,
  LineChart as LineChartIcon,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  AlertTriangle,
  Loader2,
  RefreshCw,
  Fingerprint,
  X,
} from 'lucide-react';
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
import { PrevalenceScatterPlot, type PrevalenceScatterData } from '@/components/prevalence/PrevalenceScatterPlot';
import { usePrevalenceScatterData } from '@/hooks/use-api';
import { api } from '@/lib/api';
import type { ArtifactOccurrence as ApiArtifactOccurrence } from '@/lib/api/types';
import { formatInTimeZone } from 'date-fns-tz';

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
  payload?: Array<{ payload: TimelineDataPoint }>;
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

/**
 * Parse timestamp string as UTC (handles database format without Z suffix)
 */
function parseTimestampAsUTC(timestamp: string | Date | undefined): Date {
  if (!timestamp) return new Date();
  if (timestamp instanceof Date) return timestamp;

  // If it already has timezone info (Z or +/-), parse directly
  if (timestamp.endsWith('Z') || /[+-]\d{2}:\d{2}$/.test(timestamp)) {
    return new Date(timestamp);
  }

  // Database format: "YYYY-MM-DD HH:MM:SS.ffffff" - append Z to treat as UTC
  const isoString = timestamp.replace(' ', 'T') + 'Z';
  return new Date(isoString);
}

/**
 * Extract unique hashes and domains from search results WITH their event timestamps.
 * This ensures the chart shows artifacts at the time they appeared in the search results,
 * not at the global first/last seen times from prevalence aggregation.
 */
function extractArtifactsWithTimestamps(results: SearchResult[]): {
  hashes: string[];
  domains: string[];
  hashOccurrences: ArtifactOccurrence[];
  domainOccurrences: ArtifactOccurrence[];
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
      if (domain && typeof domain === 'string' && domain.includes('.') &&
          !domain.includes(' ') && !/^\d+\.\d+\.\d+\.\d+$/.test(domain)) {
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

    // Extract domains from URL fields
    extractDomainFromUrl(fields.url);
    extractDomainFromUrl(fields.http_referrer);
    extractDomainFromUrl(fields.file_path);  // Sometimes contains URLs
  }

  return {
    hashes: Array.from(hashes).slice(0, 50),
    domains: Array.from(domains).slice(0, 50),
    hashOccurrences,
    domainOccurrences,
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
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const lastFetchedKeyRef = useRef<string | null>(null);
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
  const slimExtracted = useMemo(() => extractArtifactsWithTimestamps(results), [results]);
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
    };
  }, [mode, isAssetMode, slimHasArtifacts, artifactFetchKey, _query, timeRange]);

  // Only trust fetched rows that belong to the CURRENT query + window; a stale
  // set from a prior query is ignored (→ empty until the new fetch resolves).
  const extractedData = useMemo(() => {
    if (slimHasArtifacts) return slimExtracted;
    const fresh =
      fetchedArtifacts && fetchedArtifacts.key === artifactFetchKey ? fetchedArtifacts.rows : [];
    return extractArtifactsWithTimestamps(fresh);
  }, [slimHasArtifacts, slimExtracted, fetchedArtifacts, artifactFetchKey]);
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
    if (timeRange?.start && timeRange?.end) {
      const start = new Date(timeRange.start).getTime();
      const end = new Date(timeRange.end).getTime();
      if (!isNaN(start) && !isNaN(end)) {
        return [start, end];
      }
    }
    return null;
  }, [timeRange]);

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
      return effectiveRange;
    }
    return ['dataMin', 'dataMax'];
  }, [effectiveRange, staticMode]);

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
    prevalenceMap: Map<string, { hostCount: number; isRare: boolean; prevalenceScore: number; totalOccurrences: number; envFirstSeen: Date }>,
    artifactType: 'hash' | 'domain',
  ): PrevalenceScatterData['hashPoints'] => {
    return occurrences
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
        };
      });
  }, []);

  // Fetch scatter data when panel is opened and artifacts change
  const loadScatterData = useCallback(async (maxHostCountOverride?: number) => {
    // In asset mode, use the dedicated endpoint that does server-side prevalence filtering
    if (isAssetMode && assetContext && timeRange) {
      const effectiveMaxHostCount = maxHostCountOverride ?? assetMaxHostCount;
      const assetKey = JSON.stringify({
        asset: true,
        ...assetContext,
        timeRange,
        maxHostCount: effectiveMaxHostCount,
      });
      if (assetKey === lastFetchedKeyRef.current) return;

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
          totalOccurrences: number; envFirstSeen: Date;
        }>();
        for (const p of response.hash_prevalence) {
          hashPrevalenceMap.set(p.artifact.toLowerCase(), {
            hostCount: p.host_count, isRare: p.is_rare,
            prevalenceScore: p.prevalence_score, totalOccurrences: p.total_occurrences,
            envFirstSeen: new Date(p.first_seen),
          });
        }

        const domainPrevalenceMap = new Map<string, {
          hostCount: number; isRare: boolean; prevalenceScore: number;
          totalOccurrences: number; envFirstSeen: Date;
        }>();
        for (const p of response.domain_prevalence) {
          domainPrevalenceMap.set(p.artifact.toLowerCase(), {
            hostCount: p.host_count, isRare: p.is_rare,
            prevalenceScore: p.prevalence_score, totalOccurrences: p.total_occurrences,
            envFirstSeen: new Date(p.first_seen),
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
        const totalUnfilteredArtifacts = response.hash_prevalence.length + response.domain_prevalence.length;

        setScatterData({
          hashPoints,
          domainPoints,
          rarityThreshold: response.rarity_threshold,
          maxArtifactHostCount,
          totalUnfilteredArtifacts: totalUnfilteredArtifacts > 0 ? totalUnfilteredArtifacts : undefined,
        });
        lastFetchedKeyRef.current = assetKey;
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load prevalence data');
        lastFetchedKeyRef.current = null;
      } finally {
        setIsLoading(false);
      }
      return;
    }

    // Non-asset mode: use artifacts extracted from search results
    if (!hasArtifacts) {
      setScatterData(null);
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
    if (currentKey === lastFetchedKeyRef.current) {
      return;
    }

    // NAN-1700: new artifact set/window — drop the previous (now stale) enriched
    // data so the pending points render immediately for THIS search instead of
    // the old dots lingering until the new fetch lands.
    setScatterData(null);
    setIsLoading(true);
    setError(null);

    try {
      const response = await fetchScatterDataRef.current({
        artifacts: {
          hashes: extractedData.hashes,
          domains: extractedData.domains,
          ips: [],
        },
        window: timeWindow,
      });

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

      // Merge per-event timestamps (from extractedData) with environment-wide
      // prevalence stats (from API). X-axis uses event timestamps
      // so the scatter spreads across the search timeframe.
      const hashPoints: PrevalenceScatterData['hashPoints'] = extractedData.hashOccurrences
        .map((occ) => {
          const prevalence = hashPrevalenceMap.get(occ.artifact);
          return {
            artifact: occ.artifact,
            artifactType: 'hash' as const,
            hostCount: prevalence?.hostCount ?? 0,
            firstSeen: occ.eventTimestamp,
            lastSeen: occ.eventTimestamp,
            totalOccurrences: occ.occurrenceCount,
            isRare: prevalence?.isRare ?? false,
            prevalenceScore: prevalence?.prevalenceScore ?? 0,
            // NAN-1699: no event-time fallback — "new to env" must key off a REAL
            // env-first-seen, not the occurrence time, or every miss looks new.
            envFirstSeen: prevalence?.envFirstSeen,
          };
        });

      const domainPoints: PrevalenceScatterData['domainPoints'] = extractedData.domainOccurrences
        .map((occ) => {
          const prevalence = domainPrevalenceMap.get(occ.artifact);
          return {
            artifact: occ.artifact,
            artifactType: 'domain' as const,
            hostCount: prevalence?.hostCount ?? 0,
            firstSeen: occ.eventTimestamp,
            lastSeen: occ.eventTimestamp,
            totalOccurrences: occ.occurrenceCount,
            isRare: prevalence?.isRare ?? false,
            prevalenceScore: prevalence?.prevalenceScore ?? 0,
            // NAN-1699: no event-time fallback — "new to env" must key off a REAL
            // env-first-seen, not the occurrence time, or every miss looks new.
            envFirstSeen: prevalence?.envFirstSeen,
          };
        });

      setScatterData({
        hashPoints,
        domainPoints,
        rarityThreshold: response.rarity_threshold,
      });
      lastFetchedKeyRef.current = currentKey;
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load prevalence data');
      // NAN-1700: DON'T mark the key as fetched on failure, or the Retry button
      // (and a later re-open) hit the dedup guard and can never recover — mirror
      // the asset path which nulls it. More visible now that prefetch can fail in
      // the background before the analyst ever opens Rarity.
      lastFetchedKeyRef.current = null;
      setMode('timeline');
    } finally {
      setIsLoading(false);
    }
  // Note: fetchScatterData accessed via stable ref (fetchScatterDataRef) to avoid
  // cascading identity changes from useMutation on every render
  }, [extractedData, hasArtifacts, timeWindow, isAssetMode, assetContext, timeRange, buildScatterPoints, assetMaxHostCount]);

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
      loadScatterData();
    }
  }, [hasArtifacts, collapsed, loadScatterData, isAssetMode, assetContext]);

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
                      artifactFetchLoading
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
            {mode === 'prevalence' && isLoading && <Loader2 className="w-3.5 h-3.5 animate-spin text-muted-foreground" />}
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
                      data={timelineData}
                      barCategoryGap={0}
                      onClick={staticMode ? undefined : (e) => onTimelineClick(e as any)}
                      onMouseDown={staticMode ? undefined : (e) => onMouseDown({ activeLabel: e?.activeLabel as any })}
                      onMouseMove={staticMode ? undefined : (e) => onMouseMove({ activeLabel: e?.activeLabel as any })}
                      onMouseUp={staticMode ? undefined : onMouseUp}
                      onMouseLeave={staticMode ? undefined : onMouseUp}
                      style={{ cursor: staticMode ? 'default' : 'crosshair' }}
                    >
                      <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" vertical={false} />
                      <XAxis dataKey="timestamp" type="number" domain={xDomain} ticks={xAxisTicks} tickFormatter={formatAxisLabel} stroke="#6b7280" fontSize={10} tickLine={false} axisLine={false} minTickGap={50} tick={{ fill: '#9ca3af' }} allowDataOverflow={true} />
                      <YAxis stroke="#6b7280" fontSize={10} tickLine={false} axisLine={false} width={55} tickFormatter={formatYAxisTick} tick={{ fill: '#9ca3af' }} />
                      <Tooltip content={<HistogramTooltip bucketInterval={bucketInterval} formatTime={formatTooltipTime} />} cursor={{ fill: 'rgba(255,255,255,0.05)' }} />
                      <Bar dataKey="events" fill="var(--primary)" radius={0} minPointSize={2} />
                      {!staticMode && refAreaLeft && refAreaRight && <ReferenceArea x1={refAreaLeft} x2={refAreaRight} strokeOpacity={0.3} fill="var(--primary)" fillOpacity={0.2} />}
                    </BarChart>
                  ) : chartType === 'line' ? (
                    <LineChart
                      data={timelineData}
                      onClick={staticMode ? undefined : (e) => onTimelineClick(e as any)}
                      onMouseDown={staticMode ? undefined : (e) => onMouseDown({ activeLabel: e?.activeLabel as any })}
                      onMouseMove={staticMode ? undefined : (e) => onMouseMove({ activeLabel: e?.activeLabel as any })}
                      onMouseUp={staticMode ? undefined : onMouseUp}
                      onMouseLeave={staticMode ? undefined : onMouseUp}
                      style={{ cursor: staticMode ? 'default' : 'crosshair' }}
                    >
                      <defs><linearGradient id="lineGradient" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="var(--primary)" stopOpacity={1} /><stop offset="100%" stopColor="var(--primary)" stopOpacity={0.6} /></linearGradient></defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" vertical={false} />
                      <XAxis dataKey="timestamp" type="number" domain={xDomain} ticks={xAxisTicks} tickFormatter={formatAxisLabel} stroke="#6b7280" fontSize={10} tickLine={false} axisLine={false} minTickGap={30} tick={{ fill: '#9ca3af' }} allowDataOverflow={true} />
                      <YAxis stroke="#6b7280" fontSize={10} tickLine={false} axisLine={false} width={55} tickFormatter={formatYAxisTick} tick={{ fill: '#9ca3af' }} />
                      <Tooltip content={<HistogramTooltip bucketInterval={bucketInterval} formatTime={formatTooltipTime} />} />
                      <Line type="monotone" dataKey="events" stroke="url(#lineGradient)" strokeWidth={2} dot={{ fill: 'var(--primary)', strokeWidth: 0, r: 3 }} activeDot={{ fill: 'var(--primary)', strokeWidth: 0, r: 5 }} />
                      {!staticMode && refAreaLeft && refAreaRight && <ReferenceArea x1={refAreaLeft} x2={refAreaRight} strokeOpacity={0.3} fill="var(--primary)" fillOpacity={0.2} />}
                    </LineChart>
                  ) : (
                    <AreaChart
                      data={timelineData}
                      onClick={staticMode ? undefined : (e) => onTimelineClick(e as any)}
                      onMouseDown={staticMode ? undefined : (e) => onMouseDown({ activeLabel: e?.activeLabel as any })}
                      onMouseMove={staticMode ? undefined : (e) => onMouseMove({ activeLabel: e?.activeLabel as any })}
                      onMouseUp={staticMode ? undefined : onMouseUp}
                      onMouseLeave={staticMode ? undefined : onMouseUp}
                      style={{ cursor: staticMode ? 'default' : 'crosshair' }}
                    >
                      <defs><linearGradient id="areaGradient" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="var(--primary)" stopOpacity={0.4} /><stop offset="100%" stopColor="var(--primary)" stopOpacity={0.05} /></linearGradient></defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" vertical={false} />
                      <XAxis dataKey="timestamp" type="number" domain={xDomain} ticks={xAxisTicks} tickFormatter={formatAxisLabel} stroke="#6b7280" fontSize={10} tickLine={false} axisLine={false} minTickGap={30} tick={{ fill: '#9ca3af' }} allowDataOverflow={true} />
                      <YAxis stroke="#6b7280" fontSize={10} tickLine={false} axisLine={false} width={55} tickFormatter={formatYAxisTick} tick={{ fill: '#9ca3af' }} />
                      <Tooltip content={<HistogramTooltip bucketInterval={bucketInterval} formatTime={formatTooltipTime} />} />
                      <Area type="monotone" dataKey="events" stroke="var(--primary)" strokeWidth={2} fill="url(#areaGradient)" />
                      {!staticMode && refAreaLeft && refAreaRight && <ReferenceArea x1={refAreaLeft} x2={refAreaRight} strokeOpacity={0.3} fill="var(--primary)" fillOpacity={0.2} />}
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
                    <Button variant="ghost" size="sm" onClick={() => loadScatterData()} className="ml-4 text-muted-foreground hover:text-primary"><RefreshCw className="w-3 h-3 mr-1" />Retry query</Button>
                  </div>
                ) : (scatterData ?? pendingScatterData) ? (
                  // NAN-1700: render immediately with pending points (event-time
                  // positions) and let the enriched scatterData animate the rarity
                  // in when it lands — no full-panel spinner blocking the view.
                  <PrevalenceScatterPlot data={(scatterData ?? pendingScatterData)!} onArtifactClick={handleArtifactClick} onSelectionChange={handleSelectionChange} height={180} loading={isLoading} timeRange={timeRange} onMaxHostCountChange={isAssetMode ? handleMaxHostCountChange : undefined} />
                ) : (isLoading || artifactFetchLoading) ? (
                  <div className="flex items-center justify-center py-8 text-muted-foreground text-sm"><Loader2 className="w-4 h-4 mr-2 animate-spin" />Loading rarity index...</div>
                ) : (
                  <div className="flex items-center justify-center py-8 text-muted-foreground text-sm">No rarity data available</div>
                )}
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
