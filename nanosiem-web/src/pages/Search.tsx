// SPDX-License-Identifier: AGPL-3.0-or-later

import { AUTHORITY_UNAVAILABLE, AUTHORITY_NOTICE } from '@/lib/api/search-authority-retry';

import { useState, useMemo, useRef, useCallback, useEffect } from 'react';
import { SearchFooterProvider, PHASE2_REPORTING_MODES, type Phase2Status } from '@/components/search/footer-reporter';
import { LiveRunProvider } from '@/components/search/live-run-context';
import { useQueryClient, useQuery } from '@tanstack/react-query';
import { Link as RouterLink, useNavigate, useSearchParams } from 'react-router-dom';
import { useUserPreferences } from '@/contexts/UserPreferencesContext';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuShortcut, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';
import { DateTimeRangePicker } from '@/components/ui/date-time-range-picker';
import { formatTimelineLabel, parseUTCTimestamp } from '@/lib/date-utils';
import { buildSearchTimeline } from './search-timeline';
import { cn, injectBeforeFirstPipe, stripComments } from '@/lib/utils';
import { searchDisplayTimeMs } from '@/lib/search-timing';
import { safeRandomUUID } from '@/lib/uuid';
import { startInteractiveSearch } from './interactive-search';
import { AsyncSearchArtifact, artifactRows, asyncSearchPollDelay } from './async-search-artifact';
import { durableArtifactPageForOffset } from '@/lib/durable-result-paging';
import { captureInitialSearchPage, mergeAsyncSearchPage, reserveAsyncSearchOffset, type AsyncSearchPage, type AsyncSearchPageState } from './async-search-paging';
import {
  TAIL_FETCH_LIMIT,
  TAIL_FOLLOW_STALL_CHECK_MS,
  applyTailBatch,
  collectTailPages,
  emptyTailState,
  flushTailBuffer,
  rememberTailKeys,
  selectTailRows,
  tailArmRows,
  tailCountedArrivals,
  tailFollowActivity,
  tailFollowConnecting,
  tailFollowEnded,
  tailFollowOpened,
  tailFollowOutcome,
  tailFollowStalled,
  tailFollowsRange,
  tailPrependEligible,
  tailSupervisor,
  tailSupervisorTick,
  TAIL_STALE_GUARD_MS,
  tailWatermark,
  tailWindow,
  type TailState,
} from './search-tail';
import {
  advanceTailHistogram,
  logTailArrivals,
  reanchorTailHistogram,
  tailHistogramCutoff,
  tailReanchorDue,
  tailReanchorTrusted,
  tailRollingRangeLabel,
} from './search-tail-histogram';
import {
  displayedHistogram,
  holdTimelineForRun,
  PENDING_TIMELINE,
  searchTimelineIdentity,
  type HeldTimeline,
} from './search-timeline-hold';
import {
  Search as SearchIcon,
  ChevronDown,
  Save,
  Code,
  X,
  Square,
  Shield,
  Link2,
  Check,
  Copy,
  ChevronRight,
  Database,
  Layers,
  Clock,
  CircleCheck,
  FileSearch,
  Zap,
  CalendarClock,
  LayoutDashboard,
  AlertTriangle,
  Info,
  List,
  MoreHorizontal,
  ArrowLeft,
  GitBranch,
  MessageSquare,
  CornerDownLeft,
  Sparkles,
  LayoutGrid,
  Share2,
  Activity,
  Menu,
  Settings2,
  RotateCcw,
} from 'lucide-react';
import { LoadingIcon } from '@/components/icons/LoadingIcon';
import { PivtIcon } from '@/components/icons/PivtIcon';
import {
  useSearch,
  useSearchSql,
  useExplainQuery,
  useFieldStats,
  useSearchFieldValues,
  useSavedSearches,
  useSharedSearches,
  useCreateSavedSearch,
  useDeleteSavedSearch,
  useShareSavedSearch,
  useCreateSharedSearch,
  useGetSharedSearch,
  useMelodStatus,
  useStoreQueryExplanation,
  useGetQueryExplanation,
  toApiTimeRange,
  type TimeRangeValue
} from '@/hooks/use-api';
import { useScrollContainer } from '@/contexts/ScrollContainerContext';
import { api, ApiClientError } from '@/lib/api';
import type { ApiError, ParseErrorDetails, MelodApiResponse } from '@/lib/api';
import { useMelodJob } from '@/enterprise/hooks/use-melod-job';
import { useAuth } from '@/contexts/AuthContext';
import { useSearchHistory } from '@/hooks/useSearchHistory';
import { searchQueryForUrl } from '@/lib/search-query-url';
import { repeatsRun, resolveRunTimeRange, searchRunStart, urlTimeRange, type SearchRunScope, type SearchRunStart } from './search-run-scope';
import { formatTimeWindowLabel, readTimeRangeParams, writeTimeRangeParams } from '@/lib/time-range';
import { useIsMobile } from '@/hooks/use-mobile';
import { Sheet, SheetContent, SheetTitle } from '@/components/ui/sheet';
import { useNotebookCapture } from '@/enterprise/contexts/NotebookContext';
import { TimelineVisualization, FieldsPanel, FIELD_STATS_PINNED_COLUMNS, SearchResults, SearchQueryInput, SavedQueriesPalette, SearchJobsModal, PrevalenceSlider, DatasetSelector, type FieldStat } from '@/components/search';
import { AnalyzeView } from '@/enterprise/components/search/AnalyzeView';
import { useCapabilities } from '@/hooks/use-capabilities';
import { tenantSearchSurface } from '@/lib/tenant-capabilities';
import { ScheduleReportDialog, type ScheduleReportPreset } from '@/components/reports/ScheduleReportDialog';
import { useHereCardOverride } from '@/contexts/PageContext';
import type { SearchJobSummary } from '@/lib/api';
import type { EventCompleteness, QueryWarning, RetroResponse, SearchJobResultPage, SearchJobStatus } from '@/lib/api/types';
import { primeDurableRetroResult } from '@/components/search/retro/useRetro';
import { registerDynamicFields } from '@/components/editor';
import { SearchDemoHint } from '@/components/DemoHints';
import { SearchStatsBar } from '@/components/search/SearchStatsBar';
import { AddToDashboardDialog } from '@/components/dashboard';
import { nplQuotedBody } from '@/lib/npl-quote';
import { browserTenantRuntime } from '@/lib/tenant-runtime';
import { flattenEventFields } from '@/components/search/event-flatten';
// NAN-2209: shared with SearchResults so both group-by entry points and the
// query-rewrite paths split the pipeline identically (regex-aware).
import { hasStatsPipeline, getBaseSearch, getPipeCommands, buildGroupByQuery } from '@/lib/npl-pipeline';
import { Checkbox } from '@/components/ui/checkbox';

interface SearchResult {
  id: string;
  timestamp: Date;
  source: string;
  fields: Record<string, unknown>;
  fullEvent?: boolean;
}

function durableResultWarnings(
  result: NonNullable<SearchJobStatus['durable_result']>,
  pages: number,
): QueryWarning[] | undefined {
  const warnings: QueryWarning[] = [];
  if (result.has_more) {
    warnings.push({
      severity: 'warning',
      code: 'DURABLE_RESULT_TRUNCATED',
      message: `This job reached its ${result.rows.toLocaleString()}-row result envelope; additional matching rows exist.`,
      impact: 'The visible rows are not a complete export. Narrow the query while sliced result streaming is prepared.',
    });
  }
  if (pages > 1) {
    warnings.push({
      severity: 'info',
      code: 'DURABLE_RESULT_PAGED',
      message: `This durable result has ${pages.toLocaleString()} pages.`,
      impact: 'Additional rows load through the same results view as you page or scroll.',
    });
  }
  return warnings.length > 0 ? warnings : undefined;
}

function saveDurableDownload(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

function eventField(row: Record<string, unknown>, path: string): unknown {
  if (Object.prototype.hasOwnProperty.call(row, path)) return row[path];
  return path.split('.').reduce<unknown>((value, segment) => {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
    return (value as Record<string, unknown>)[segment];
  }, row);
}

function eventTimestamp(row: Record<string, unknown>): Date {
  return parseUTCTimestamp(String(eventField(row, 'time') ?? row.timestamp ?? ''));
}

function eventSource(row: Record<string, unknown>): string {
  const logSource = String(eventField(row, 'metadata.log_source') ?? row.source_type ?? '');
  if (logSource === 'signals' || logSource === 'findings') {
    return String(eventField(row, 'unmapped.risk_entity') ?? 'signal');
  }
  return String(
    eventField(row, 'device.hostname')
      ?? eventField(row, 'src_endpoint.hostname')
      ?? eventField(row, 'src_endpoint.ip')
      ?? row.src_host
      ?? row.src_ip
      ?? 'unknown',
  );
}

function eventKeyContext(row: Record<string, unknown>, ocsf: boolean): string {
  const specs = ocsf
    ? [
        ['src_endpoint.ip', 'src_endpoint.ip'],
        ['dst_endpoint.ip', 'dst_endpoint.ip'],
        ['actor.user.name', 'actor.user.name'],
        ['http_request.url.url_string', 'http_request.url.url_string'],
        ['device.hostname', 'device.hostname'],
      ]
    : [
        ['src_ip', 'src_ip'],
        ['dst_ip', 'dst_ip'],
        ['user', 'user'],
        ['url', 'url'],
        ['hostname', 'hostname'],
      ];
  return specs
    .flatMap(([path, label]) => {
      const value = eventField(row, path);
      return value == null || value === '' ? [] : [`${label}: ${String(value)}`];
    })
    .join(', ');
}

// Live tail interval presets
const TAIL_INTERVALS = [
  { label: '5s',  ms: 5000 },
  { label: '15s', ms: 15000 },
  { label: '30s', ms: 30000 },
  { label: '45s', ms: 45000 },
  { label: '1m',  ms: 60000 },
  { label: '5m',  ms: 300000 },
] as const;

// Removed getDefaultQuery - we now use empty string and rely on placeholder

// Check if query has aggregate commands (stats, table, timechart, top, rare, transaction) outside of regex/quotes
const checkIfAggregateQuery = (q: string) => {
  // First, find the actual pipe command position (not inside regex/quotes)
  let inRegex = false;
  let inQuote = false;
  let escapeNext = false;
  
  for (let i = 0; i < q.length; i++) {
    const c = q[i];
    
    if (escapeNext) {
      escapeNext = false;
      continue;
    }
    
    if (c === '\\') {
      escapeNext = true;
      continue;
    }
    
    if (c === '"' && !inRegex) {
      inQuote = !inQuote;
      continue;
    }
    
    if (c === '/' && !inQuote) {
      if (!inRegex) {
        const before = q.substring(0, i).trimEnd();
        if (before.endsWith('=') || before.endsWith('!=')) {
          inRegex = true;
        }
      } else {
        inRegex = false;
      }
      continue;
    }
    
    if (c === '|' && !inRegex && !inQuote) {
      // Found a real pipe - check what command follows
      const afterPipe = q.substring(i + 1).trim().toLowerCase();
      if (afterPipe.startsWith('stats') ||
          afterPipe.startsWith('table') ||
          afterPipe.startsWith('timechart') ||
          afterPipe.startsWith('top') ||
          afterPipe.startsWith('rare') ||
          afterPipe.startsWith('anomaly') ||
          afterPipe.startsWith('transaction') ||
          afterPipe.startsWith('return')) {
        return true;
      }
      // Prevalence returns event ROWS when it enriches (enrich=true) OR filters on a
      // prevalence field (hash_prevalence/domain_prevalence <op> N) — only the bare
      // summary form is a true aggregate. NAN-1695: the filter form now pushes down
      // (NAN-1691) and returns the rare events, so classifying it as aggregate skipped
      // the event field-stats path and flattened ext.* into the field picker.
      // Inspect ONLY the prevalence command segment (up to the next `|`), and require a
      // comparator — so a bare `| prevalence | where hash_prevalence < 5` (summary + a
      // later where) still classifies as aggregate.
      const prevalenceCmd = afterPipe.split('|')[0];
      if (afterPipe.startsWith('prevalence')
          && !prevalenceCmd.includes('enrich=true') && !prevalenceCmd.includes('enrich = true')
          && !/\b(hash|domain)_prevalence\b\s*(?:<=|>=|!=|=|<|>)/.test(prevalenceCmd)) {
        return true;
      }
    }
  }
  
  return false;
};

// --- Client-side search result cache for back-navigation ---
// Module-level cache survives component unmount/remount during navigation

interface CachedSearchResult {
  results: SearchResult[];
  histogramData: Array<{ time: string; count: number }>;
  serverFieldStats: Array<{ name: string; count: number; top_values: [string, number][]; cardinality?: number; sampled_rows?: number }> | null;
  // Whether serverFieldStats were computed over a reduced column set (so restore
  // can re-offer "Show all fields" / NAN-1503 auto-fetch). Null until stats land.
  fieldStatsReduced: boolean | null;
  totalCount: number;
  totalCountExact: boolean;
  executionTimeMs: number | null;
  completeness?: EventCompleteness;
  displayType: import('@/lib/api/types').DisplayType | undefined;
  columnOrder: string[] | undefined;
  generatedSql: string | null;
  costScore: number | null;
  executedQuery: string;
  isAggregateQuery: boolean;
  peakRowsScanned: number;
  cachedAt: number;
}

const searchResultCache = new Map<string, CachedSearchResult>();
let searchResultCacheRuntimeKey = browserTenantRuntime.current().key;
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

function buildCacheKey(
  query: string,
  timeRange: TimeRangeValue,
  mode: string,
  // NAN-1825: identical query text against different datasets (logs vs
  // spans/metrics/risk) must not share a cache entry, or switching datasets
  // silently serves results from the wrong table.
  dataset: import('@/lib/api/types').SearchDataset = 'logs',
): string {
  const runtimeKey = browserTenantRuntime.current().key;
  if (runtimeKey !== searchResultCacheRuntimeKey) {
    searchResultCache.clear();
    searchResultCacheRuntimeKey = runtimeKey;
  }
  const timeKey = timeRange.type === 'custom' && timeRange.start && timeRange.end
    ? `${timeRange.start.toISOString()}_${timeRange.end.toISOString()}`
    : timeRange.preset;
  return `${runtimeKey}:${mode}:${dataset}:${query}:${timeKey}`;
}

// The field rail and expanded event must discover the exact same canonical
// leaves. In particular, OCSF objects (`actor.process.file.*`, `device.*`, …)
// cannot stay as opaque top-level objects here: the stats reducer intentionally
// skips objects, which previously made almost every mapped OCSF leaf disappear
// from the rail while remaining visible in the expanded record.
const flattenFieldsForStats = (
  fields: Record<string, unknown>,
  isOcsf: boolean,
  promotedNames: Set<string>,
): [string, unknown][] => flattenEventFields(fields, isOcsf, '', promotedNames);

// NAN-1427: derive the column set the field index needs from the rows the
// analyst can actually see, plus the pinned "Selected" columns. The server's
// field-stats query reads every requested column over all matching rows, so
// the default request covers visible + pinned columns only (measured 50x less
// I/O than the full ~90-column inventory); the panel's "Index all fields"
// action refetches without `columns` for the full inventory. Unknown names
// (ext-JSON keys etc.) are dropped server-side by intersection with the live
// table inventory.
const collectFieldStatsColumns = (
  results: SearchResult[],
  isOcsf: boolean,
  promotedNames: Set<string>,
): string[] => {
  const cols = new Set<string>(FIELD_STATS_PINNED_COLUMNS);
  // First 200 rows are plenty to discover the visible column population.
  for (const result of results.slice(0, 200)) {
    if (result?.fields && typeof result.fields === 'object' && result.fields !== null) {
      for (const [key] of flattenFieldsForStats(result.fields, isOcsf, promotedNames)) {
        cols.add(key);
      }
    }
  }
  return Array.from(cols);
};

// Map API preset format to UI display format
const timeRangePresetToDisplay: Record<string, string> = {
  'last_15_minutes': 'Last 15 minutes',
  'last_hour': 'Last hour',
  'last_4_hours': 'Last 4 hours',
  'last_24_hours': 'Last 24 hours',
  'last_7_days': 'Last 7 days',
  'last_30_days': 'Last 30 days',
};

export function Search() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  // The router's current params for async callbacks (NAN-3263's re-anchor
  // writes the rolling window into the URL after an await).
  const searchParamsRef = useRef(searchParams);
  searchParamsRef.current = searchParams;
  const queryClient = useQueryClient();
  const { defaultTimeRange, queryMode: userQueryMode } = useUserPreferences();
  const { user, hasPermission, isAuthenticated } = useAuth();
  const { capabilities, tenantPlan } = useCapabilities();
  // NAN-2361 wave 8: what the Search runtime behind this session serves. Each
  // flag names its backing route (see `SearchSurface`); nothing on this page
  // branches on the deployment mode. Saved searches, history, sharing by URL,
  // AI, dashboards, reports, rules, enrichment controls and the histogram all
  // have tenant-scoped routes and are ungated.
  const searchSurface = useMemo(() => tenantSearchSurface(tenantPlan), [tenantPlan]);
  const resultsScrollContainer = useScrollContainer();
  const durableExecution = searchSurface.durableExecution;
  // Datasets beyond `logs` are a runtime capability, not a UI preference.
  const datasetChoices = searchSurface.datasets;
  const isSearchDataset = useCallback(
    (value: string | null): value is import('@/lib/api/types').SearchDataset =>
      value !== null && (datasetChoices as readonly string[]).includes(value),
    [datasetChoices],
  );
  // NAN-2361: the router basename carries the tenant prefix.
  const searchPagePath = '/search';

  useDocumentTitle('Search');

  // Parse URL params
  const urlQuery = searchParams.get('q') || '';
  const urlMode = (searchParams.get('mode') as 'piped' | 'sql' | 'natural') || 'piped';
  const urlShortId = searchParams.get('s') || '';
  const urlAutoRun = searchParams.get('run') === 'true';
  const urlJobId = searchParams.get('job_id') || '';
  const urlAiMode = searchParams.get('ai') === 'true'; // Enable AI refinement mode
  const urlPrevalence = searchParams.get('prevalence') ? parseInt(searchParams.get('prevalence')!, 10) : 100;

  const getInitialTimeRange = (): TimeRangeValue => {
    const fromUrl = readTimeRangeParams(searchParams);
    if (fromUrl) return fromUrl;
    // Use user's preferred default time range
    const displayPreset = timeRangePresetToDisplay[defaultTimeRange] || 'Last hour';
    return { type: 'preset', preset: displayPreset };
  };

  // Core state
  const [queryMode, setQueryMode] = useState<'piped' | 'sql'>(
    !searchSurface.rawSql || urlMode === 'natural' ? 'piped' : urlMode as 'piped' | 'sql',
  );
  // NAN-1534: observability dataset the nPL pipeline runs against. "logs" (the
  // UDM lane) is the default; "spans"/"metrics" target the OTLP tables. The
  // dedicated /observability explorers are the primary span/metric surfaces —
  // this toggle lets analysts run ad-hoc nPL against those tables in-place.
  // "risk" (NAN-1805) targets the derived accumulated-entity-risk grain.
  const [dataset, setDataset] = useState<import('@/lib/api/types').SearchDataset>(() => {
    const d = searchParams.get('dataset');
    return isSearchDataset(d) ? d : 'logs';
  });
  const [query, setQuery] = useState(urlQuery || '');
  const [executedQuery, setExecutedQuery] = useState(''); // Query that was actually executed (for highlighting)
  const [naturalLanguageQuery, setNaturalLanguageQuery] = useState(urlMode === 'natural' ? urlQuery : '');
  const [timeRange, setTimeRange] = useState<TimeRangeValue>(getInitialTimeRange());
  const [searchResults, setSearchResults] = useState<SearchResult[]>([]);
  // Mirror of searchResults for callbacks that fire outside the render cycle
  // (e.g. SSE onCompleted needs the streamed rows to derive the field-stats
  // column set, NAN-1427).
  const searchResultsRef = useRef<SearchResult[]>([]);
  useEffect(() => { searchResultsRef.current = searchResults; }, [searchResults]);
  const [searchError, setSearchError] = useState<ApiError | null>(null);
  const [isCorrectingQuery, setIsCorrectingQuery] = useState(false);
  const [isReviewingQuery, setIsReviewingQuery] = useState(false);
  const [queryReviewSuggestions, setQueryReviewSuggestions] = useState<import('@/lib/api/types').ReviewQuerySuggestion[]>([]);
  const [isSearching, setIsSearching] = useState(false);
  const [hasSearched, setHasSearched] = useState(false);
  const [isAggregateQuery, setIsAggregateQuery] = useState(false);
  const [displayType, setDisplayType] = useState<import('@/lib/api/types').DisplayType | undefined>(undefined);
  const [columnOrder, setColumnOrder] = useState<string[] | undefined>(undefined);


  // Async search job state
  const [asyncJobId, setAsyncJobId] = useState<string | null>(null);
  const [asyncJobStatus, setAsyncJobStatus] = useState<import('@/lib/api/types').SearchJobStatusValue | null>(null);
  const [asyncJobProgress, setAsyncJobProgress] = useState<import('@/lib/api/types').SearchJobProgress | null>(null);
  const [queuePosition, setQueuePosition] = useState<number | null>(null);
  const [estimatedWait, setEstimatedWait] = useState<number | null>(null);
  const asyncJobPollingRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // SSE streaming state
  const [isStreamingResults, setIsStreamingResults] = useState(false);
  const sseControllerRef = useRef<AbortController | null>(null);

  // Live tail state
  const [tailActive, setTailActive] = useState(false);
  const [tailInterval, setTailInterval] = useState(15000);
  // NAN-2836: set when picking a fixed past range stopped the tail, so the
  // footer says why the tail went quiet instead of it just vanishing.
  const [tailStoppedForRange, setTailStoppedForRange] = useState(false);
  useEffect(() => { if (tailActive) setTailStoppedForRange(false); }, [tailActive]);
  const tailTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const tailFollowControllerRef = useRef<AbortController | null>(null);
  const startTailFollowRef = useRef<() => void>(() => {});
  // NAN-3244: follow/poll supervisor (see search-tail.ts). One tick per
  // interval decides whether to poll and whether to reconnect the follow.
  const tailSupervisorRef = useRef(tailSupervisor());
  const tailTickRef = useRef<() => void>(() => {});
  // One-shot tick at the follow's reconnect time, so the backoff is honoured
  // exactly instead of rounding up to the next interval tick.
  const tailRetryTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  // Arms that one-shot tick for a `down` follow (shared by every end path).
  const scheduleTailRetryRef = useRef<(nowMs: number) => void>(() => {});
  // When the page's own search started (0 = idle). Blocks tail ticks for at
  // most TAIL_STALE_GUARD_MS, so a stuck flag cannot kill the tail.
  const tailSearchingSinceRef = useRef(0);
  // Bumped whenever a real search resets the tail; late tail responses from
  // before the reset are dropped (NAN-2557) without depending on the search
  // request id, which also moves on infinite-scroll pages.
  const tailEpochRef = useRef(0);
  // NAN-2551: tail arrivals live in their own list rendered in front of
  // `searchResults`. Keeping them out of `searchResults` is what makes the
  // prepend free: artifact offsets, `asyncPageStateRef`, the page-bound count
  // scope and every `searchResults.length` pagination sum stay exactly as the
  // paged search left them (NAN-2512 / NAN-2514).
  const [tailState, setTailState] = useState<TailState<SearchResult>>(() => emptyTailState<SearchResult>());
  const tailStateRef = useRef(tailState);
  useEffect(() => { tailStateRef.current = tailState; }, [tailState]);
  // Keys of everything on screen, so the deliberate window overlap that closes
  // the visibility-lag gap cannot re-prepend a row the analyst already has.
  const tailSeenKeysRef = useRef<Set<string>>(new Set());
  // Newest event time seen, clamped to now (see search-tail.ts).
  const tailWatermarkRef = useRef(0);
  // When the in-flight tail poll started (0 = none).
  const tailPollStartedAtRef = useRef(0);
  // Virtualiser range start. Arrivals are held back while the analyst is
  // reading further down, so the viewport never jumps under them.
  const tailAtTopRef = useRef(true);
  const runTailRefreshRef = useRef<() => void>(() => {});
  // NAN-3254: the tail keeps the EVENT STREAM moving. Arrivals newer than this
  // cutoff are counted into the histogram; anything at or before it was in the
  // histogram the search returned (see search-tail-histogram.ts).
  const tailHistogramCutoffRef = useRef(0);
  // Where the chart's window ends while tailing (epoch ms); null = the picker's.
  const [tailChartEndMs, setTailChartEndMs] = useState<number | null>(null);
  const advanceTailTimelineRef = useRef<(arrivalTimesMs: number[]) => void>(() => {});
  // NAN-3263: the live count is re-anchored on a server read of the rolling
  // window (see search-tail-histogram.ts). Arrival times after the cutoff are
  // kept so an anchor that lands can re-apply the ones it could not count.
  const tailArrivalLogRef = useRef<number[]>([]);
  const tailReanchorRef = useRef<{ lastRequestedMs: number; controller: AbortController | null }>({
    lastRequestedMs: 0,
    controller: null,
  });
  const reanchorTailTimelineRef = useRef<(tailIntervalMs: number) => void>(() => {});

  // Transient hl-wipe class when a search run completes — drives the
  // left→right reveal on result <mark> highlights (index.css). Skipped
  // during live tail (replaying it every refresh tick reads as noise).
  const [hlWipe, setHlWipe] = useState(false);
  const hlWipeWasSearchingRef = useRef(false);
  useEffect(() => {
    const was = hlWipeWasSearchingRef.current;
    hlWipeWasSearchingRef.current = isSearching;
    if (isSearching && !was) {
      // A new run inside the wipe window cancels the reset timer via this
      // effect's cleanup — clear explicitly so the class re-toggles (CSS
      // animations fire on class addition, not presence) on completion.
      setHlWipe(false);
      return;
    }
    if (was && !isSearching && !tailActive) {
      setHlWipe(true);
      const t = setTimeout(() => setHlWipe(false), 1500);
      return () => clearTimeout(t);
    }
  }, [isSearching, tailActive]);

  const artifactRef = useRef<{
    pager: AsyncSearchArtifact;
    requestId: string;
    nextOffset: number;
    busy: boolean;
  } | null>(null);

  // Pagination state for tabular views (stats, table)
  const [tablePage, setTablePage] = useState(0);
  const [tablePageSize, setTablePageSize] = useState(50);
  const [durableResultCursor, setDurableResultCursor] = useState<{
    jobId: string;
    pages: number;
    pageRows: number;
    loadedPage: number;
    rowOffset: number;
  } | null>(null);

  // Prevalence filter state (0-100, lower = rarer, 100 = show all)
  const [prevalenceMax, setPrevalenceMax] = useState(urlPrevalence);

  // UI state
  const [expandedFields, setExpandedFields] = useState<Set<string>>(new Set());
  const [showSql, setShowSql] = useState(false);
  const [generatedSql, setGeneratedSql] = useState<string | null>(null);
  const [saveSearchName, setSaveSearchName] = useState('');
  const [saveSearchDescription, setSaveSearchDescription] = useState('');
  const [saveSearchShared, setSaveSearchShared] = useState(false);
  const [saveDialogOpen, setSaveDialogOpen] = useState(false);
  const [savedQueriesOpen, setSavedQueriesOpen] = useState(false);
  const [jobsModalOpen, setJobsModalOpen] = useState(false);
  // NAN-1793: schedule a saved query as a recurring report.
  const [schedulePreset, setSchedulePreset] = useState<ScheduleReportPreset | null>(null);

  // Permission checks - Requirements: 5.3
  // GET /api/schema/fields — served on every profile (the shared app shell
  // answers the tenant lake's OCSF 1.9 universe).
  const { data: activeSchema } = useQuery({
    queryKey: ['schema-fields'],
    queryFn: () => api.getSchemaFields(),
    staleTime: Infinity,
    gcTime: Infinity,
  });
  const isOcsf = activeSchema?.schema === 'ocsf';
  const promotedSchemaFields = useMemo(
    () => new Set((activeSchema?.fields ?? []).map((field) => field.name)),
    [activeSchema],
  );

  // NAN-2361: the rarity slider's filter expression, feature-detected from the
  // ACTIVE schema rather than hardcoded per backend.
  //
  // The lake stores prevalence as OCSF `enrichments[]` entries and advertises
  // `enrichments.data.host_count`; UDM and OCSF-on-ClickHouse carry the promoted
  // scalar `prevalence_min` column. Detecting on the advertised field set means
  // one expression works on every backend, and a tenant that has not yet built a
  // prevalence derivative simply keeps the old path instead of emitting a filter
  // on a field that does not exist.
  //
  // The scalar `prevalence_*` fields (including `prevalence_min`) also resolve
  // on every lake, so saved searches, rules and dashboards written against them
  // keep working: lean parts store them as physical ingest-time columns, and an
  // open-core lake derives them from the same `enrichments[]` stamps (NAN-3451).
  // The slider still emits the canonical OCSF form.
  const prevalenceFilterClause = useCallback(
    (max: number) =>
      promotedSchemaFields.has('enrichments.data.host_count')
        ? ` | where enrichments.data.host_count <= ${max}`
        : ` | where prevalence_min <= ${max}`,
    [promotedSchemaFields],
  );

  // Active search jobs indicator — drives the badge on the More (...) chip.
  // NAN-2046: the async-job endpoints require search:execute (NAN-2032). A session
  // holding only search:view must not poll them, or every 15s poll 403-loops. Gate
  // the query on the capability so the badge simply stays empty for such sessions.
  const { data: activeJobs } = useQuery({
    queryKey: ['search-jobs'],
    enabled: hasPermission('search:execute'),
    queryFn: () => api.listSearchJobs(),
    refetchInterval: (query) => {
      const data = query.state.data as SearchJobSummary[] | undefined;
      if (!data) return 15_000;
      const hasActive = data.some(j => j.status === 'queued' || j.status === 'running');
      return hasActive ? 3_000 : 15_000;
    },
    select: (jobs: SearchJobSummary[]) => jobs.filter(j => j.status === 'queued' || j.status === 'running'),
  });
  const activeJobCount = activeJobs?.length ?? 0;
  const [showBaseFields, setShowBaseFields] = useState(false);
  const [timelineCollapsed, setTimelineCollapsed] = useState(false);
  const [chartType, setChartType] = useState<'bar' | 'line' | 'area'>(() => {
    const saved = localStorage.getItem('nanosiem-chart-type');
    return saved === 'bar' || saved === 'line' || saved === 'area' ? saved : 'area';
  });
  const [baseFieldStats, setBaseFieldStats] = useState<FieldStat[]>([]);
  const [fieldsPanelExpanded, setFieldsPanelExpanded] = useState(true);
  const [fieldsPanelVisible, setFieldsPanelVisible] = useState(false); // Hide initially for cool effect
  const userToggledFieldsPanel = useRef(false); // Track manual user toggle to not fight them
  const isMobile = useIsMobile();
  const [mobileFieldsOpen, setMobileFieldsOpen] = useState(false);
  
  // Analyze mode — when true, the results area is replaced by AnalyzeView
  // (a full-page LLM analysis of the current result set). Back button in
  // AnalyzeView flips this back to false and the user lands on their
  // existing results with query + time range intact.
  const [analyzeActive, setAnalyzeActive] = useState(false);

  // ONE predicate, used with its exact inverse below. These two guards were
  // never complementary: AnalyzeView also required `hasSearched` and a non-empty
  // result set, while the results area was hidden on `analyzeActive` alone — so
  // `analyzeActive` with no results rendered NEITHER and the page went blank.
  // `pivt:summarize` sets `analyzeActive` unconditionally, so it could reach
  // exactly that state. Deriving both from one value makes the blank case
  // unrepresentable (NAN-2356).
  const showAnalyze =
    analyzeActive && capabilities.melod && hasSearched && searchResults.length > 0;

  // pivt bridge — `@summarize` from anywhere in the app fires
  // `pivt:summarize`. Route to the Analyze view the same way the
  // toolbar button does. (Router navigates to /search first if the
  // user isn't here yet, so the listener is always mounted in time.)
  // NAN-2356: only wired when meloD is available. AnalyzeView is enterprise and
  // stubs to `return null` in open builds, while `analyzeActive` ALSO hides the
  // fields + results area below — so firing this in an open build would blank
  // the whole search page.
  useEffect(() => {
    if (!capabilities.melod) return;
    const handler = () => setAnalyzeActive(true);
    window.addEventListener('pivt:summarize', handler);
    return () => window.removeEventListener('pivt:summarize', handler);
  }, [capabilities.melod]);

  // Pagination state
  const [currentPage, setCurrentPage] = useState(1);
  const [pagingComplete, setPagingComplete] = useState(false);
  const lastAsyncOffsetRef = useRef<number | null>(null);
  const asyncPageStateRef = useRef<AsyncSearchPageState<SearchResult>>({
    results: [], totalCount: 0, currentPage: 1, complete: false,
  });
  // NAN-3093: on a durable (lean) surface the timeline is asked for beside
  // the rows (`POST /api/search/histogram`), so rows paint without waiting
  // for it. Whichever of the two answers second must not undo the first:
  // the rows response carries no histogram, and its page-bound total must
  // not replace the exact total the timeline proved.
  const splitHistogramRef = useRef<{
    requestId: string;
    histogram?: Array<{ time: string; count: number }>;
    total?: number;
    rowsIn: boolean;
    startedAt: number;
    finishedAt?: number;
    published?: boolean;
  } | null>(null);
  const [totalCount, setTotalCount] = useState(0);
  // NAN-2550: false when `totalCount` is a proven lower bound rather than a
  // total (a lake page cannot cheaply produce a search-wide count). A missing
  // `total_count_exact` on the wire means an older server, so it reads as
  // "assume not exact" -- the conservative direction.
  const [totalCountExact, setTotalCountExact] = useState(true);
  /**
   * The count the page *displays* (NAN-2557).
   *
   * `totalCount` is the query's own answer for its own window and stays that:
   * every piece of paging arithmetic below (`loadMore`, the artifact bound,
   * `asyncPageStateRef`) compares it against `searchResults`, which the tail
   * never rewrites (NAN-2551). But the live tail really did put more matching
   * events on screen, and the page must not report two different totals for
   * one result set — the results header, the analyze view, the hit banner and
   * the footer all read this, and `SearchResults` gets the same sum plus
   * `prependedRowCount` so its NAN-2550 lower-bound branch can still tell the
   * paged rows from the arrivals.
   *
   * Buffered arrivals are deliberately excluded: they are not on screen yet,
   * they are counted by their own "N new events" chip, and including them
   * would make the footer disagree with the row list again.
   *
   * NAN-3254: the tail list is a rolling window, so the sum uses every arrival
   * the tail has shown (`arrived`, including rows since rolled off), not the
   * capped `rows.length` — otherwise the count froze at the cap.
   */
  const displayTotalCount = totalCount + tailCountedArrivals(tailState);
  // Peak `rows_scanned` from streaming `onProgress` SSE events. Tracked so
  // the >1M-row warning can fire on aggregate queries, whose `total_count`
  // is the post-aggregation output size (e.g. 20 rows from `head 20`) and
  // never crosses the 1M threshold on its own.
  const [peakRowsScanned, setPeakRowsScanned] = useState(0);
  const [limitWarningDismissed, setLimitWarningDismissed] = useState(false);
  const [pageSize] = useState(50);

  // pivt "Here" card override — reflects live search state so the
  // assistant can see the user's current query + result count. The
  // static Search card in the registry only gets used before a query
  // runs; as soon as results land, this override takes over.
  useHereCardOverride(
    hasSearched
      ? {
          icon: 'Search',
          title: 'Search',
          tags: queryMode === 'sql' ? ['SQL'] : ['nPL'],
          lines: [
            { label: 'query', value: query || '— (empty)' },
            {
              label: 'results',
              value:
                displayTotalCount > 0
                  ? `${displayTotalCount.toLocaleString()} events`
                  : 'no matches',
            },
          ],
          suggestions:
            displayTotalCount > 0
              ? [
                  'Summarize these results',
                  isOcsf ? 'Pivot by src_endpoint.ip' : 'Pivot by src_ip',
                  'Create a detection from this query',
                ]
              : ['Widen the time range', 'Remove a filter', 'Summarize zero-result patterns'],
        }
      : null
  );

  // Query execution time
  const [completeness, setCompleteness] = useState<EventCompleteness | undefined>();
  const [splitTiming, setSplitTiming] = useState<{ firstRowsMs: number; completionMs?: number } | null>(null);
  const [executionTimeMs, setExecutionTimeMs] = useState<number | null>(null);

  // NAN-1598: phase-2 footer status. Two-phase display modes (the primary
  // /api/search returns a marker, then the view fetches the real data) publish
  // their loading/time/count here via the SearchFooterProvider so the footer
  // reflects the real work instead of the throwaway marker query. Null between
  // searches and until the view reports.
  const [phase2, setPhase2] = useState<Phase2Status | null>(null);
  const reportPhase2 = useCallback((status: Phase2Status) => setPhase2(status), []);

  // NAN-1602: true when the displayed search was an explicit user run (→ live,
  // no "cached" badge). False on passive loads (shared link / URL restore),
  // where the cache + badge are correct. Drives the special views' initial
  // fetch bypass via LiveRunProvider.
  const [liveRun, setLiveRun] = useState(false);
  
  // Query cost score (for display in error messages)
  const [_queryCostScore, setQueryCostScore] = useState<number | null>(null);

  // Cached results banner (shown when serving from back-navigation cache)
  const [cachedResultsTimestamp, setCachedResultsTimestamp] = useState<number | null>(null);
  
  // Histogram data from API
  const [histogramData, setHistogramData] = useState<Array<{ time: string; count: number }>>([]);
  // The committed timeline, for the tail re-anchor's trust check (NAN-3267).
  const histogramDataRef = useRef(histogramData);
  histogramDataRef.current = histogramData;
  // NAN-3273: while a re-run of the same search is pending (a tail re-run, a
  // time-window roll, a refresh), the timeline keeps showing the last one it
  // had instead of an empty chart and "0 events". A run clears the histogram
  // to PENDING_TIMELINE; any install (an empty read included) replaces it and
  // so ends the hold. See search-timeline-hold.ts.
  const [timelineHold, setTimelineHold] = useState<HeldTimeline | null>(null);
  const timelineHoldRef = useRef(timelineHold);
  timelineHoldRef.current = timelineHold;
  // The search identity the committed histogram belongs to (set when a run starts).
  const timelineIdentityRef = useRef<string | null>(null);
  const executedQueryRef = useRef(executedQuery);
  executedQueryRef.current = executedQuery;

  // Asset prevalence filter (for filtering asset timeline by prevalence artifacts).
  // Setter is currently unused — the previous wiring lived inside dead asset
  // branches on the (asset-excluded) TimelineVisualization; the asset render
  // path needs its own re-wiring to drive this. Prefixed to silence TS6133
  // until that lands.
  const [assetPrevalenceFilter, _setAssetPrevalenceFilter] = useState<{
    artifacts: string[];
    filterType: 'include' | 'rare';
    timestamp?: number;
  } | null>(null);

  // Server-provided field stats (from topK query across all matching events)
  const [serverFieldStats, setServerFieldStats] = useState<Array<{
    name: string;
    count: number;
    top_values: [string, number][];
    cardinality?: number;
    sampled_rows?: number;
  }> | null>(null);

  // NAN-1427: whether the current server field stats were computed over the
  // reduced (visible + pinned) column set — gates "Index all fields".
  const [fieldStatsReduced, setFieldStatsReduced] = useState(false);
  // Parameters of the last field-stats fetch, for the "Index all fields" refetch.
  const lastFieldStatsRequestRef = useRef<{ query: string; start: string; end: string; request_id?: string; dataset?: import('@/lib/api/types').SearchDataset } | null>(null);

  
  // Share state
  const [copiedUrl, setCopiedUrl] = useState(false);
  const [copiedShortUrl, setCopiedShortUrl] = useState(false);
  const [isCreatingShortUrl, setIsCreatingShortUrl] = useState(false);
  const [shortUrlId, setShortUrlId] = useState<string | null>(urlShortId || null);
  const [showAddToDashboardDialog, setShowAddToDashboardDialog] = useState(false);

  // AI suggestion pill state
  const [showAiSuggestion, setShowAiSuggestion] = useState(false);
  const aiSuggestionTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Detect tree visualization mode - hide fields panel when in tree mode
  const isTreeView = searchResults.length > 0 && searchResults[0]?.fields?._display_type === 'tree';

  // Detect retro (IOC retrohunt) page view - fields panel stays eligible but
  // defaults to collapsed (restore-pill UX), like aggregate queries
  const isRetroView = searchResults.length > 0 && searchResults[0]?.fields?._display_type === 'retro';

  // Track previous query for breadcrumb navigation (before tree view)
  const [previousQuery, setPreviousQuery] = useState<string | null>(null);
  const previousQueryRef = useRef<string | null>(null);

  // When query changes, track the previous non-tree query for breadcrumb
  useEffect(() => {
    const currentQueryIsTree = query.includes('| tree');
    const prevQueryIsTree = previousQueryRef.current?.includes('| tree');

    // If we're switching TO a tree query from a non-tree query, save the previous
    if (currentQueryIsTree && !prevQueryIsTree && previousQueryRef.current) {
      setPreviousQuery(previousQueryRef.current);
    }
    // If we're switching away from tree view, clear the breadcrumb
    if (!currentQueryIsTree) {
      setPreviousQuery(null);
    }

    previousQueryRef.current = query;
  }, [query]);

  // Retro results default the fields panel to collapsed (restore-pill UX).
  // The display type only surfaces once results arrive, so collapse here —
  // but respect a manual user toggle so expanding sticks.
  useEffect(() => {
    if (isRetroView && !userToggledFieldsPanel.current) {
      setFieldsPanelExpanded(false);
    }
  }, [isRetroView]);

  // Helper function to convert errors to ApiError format
  const handleError = (err: unknown, fallbackMessage: string): ApiError => {
    // Handle ApiClientError instances (check by name since instanceof may not work with imports)
    if (err instanceof Error && err.name === 'ApiClientError') {
      const apiClientError = err as any; // Cast to access ApiClientError properties
      return {
        code: apiClientError.code || 'UNKNOWN_ERROR',
        message: apiClientError.message,
        details: apiClientError.details as ParseErrorDetails,
      };
    }
    
    // Handle generic API error responses
    if (err && typeof err === 'object' && 'error' in err) {
      const apiErr = err as { error: ApiError };
      return apiErr.error;
    }
    
    // Fallback for other error types
    return {
      code: 'UNKNOWN_ERROR',
      message: err instanceof Error ? err.message : fallbackMessage,
    };
  };

  // Helper function to apply a suggestion to the query
  const applySuggestion = useCallback((replacement: string) => {
    // If the replacement starts with |, append it to the current query
    // Otherwise, replace the entire query
    if (replacement.startsWith('|')) {
      // Remove the problematic token from the end and append the suggestion
      const baseQuery = query.replace(/\s+\w+\s*$/, '').trim();
      setQuery(`${baseQuery} ${replacement}`);
    } else {
      setQuery(replacement);
    }
    setSearchError(null);
  }, [query]);

  // Request AI-assisted query correction when a search fails
  // (POST /api/melod/correct-query). `capabilities.queryCorrection` is the
  // only gate: on a hosted-shared tenant it already folds in the plan, the
  // caller's permissions and the platform provider state, so no request is
  // issued while AI is not enabled for the tenant.
  const correctionInFlightRef = useRef<string | null>(null);
  const requestQueryCorrection = useCallback((errorCode: string, errorMsg: string, failedQuery: string, fieldSuggestions?: string[]) => {
    if (!capabilities.queryCorrection) return;
    // Only attempt correction for correctable error types
    const correctableCodes = ['PARSE_ERROR', 'FIELD_NOT_FOUND', 'DATABASE_ERROR', 'QUERY_ERROR', 'INTERNAL_ERROR', 'JOB_FAILED'];
    if (!correctableCodes.includes(errorCode)) return;
    // Don't correct empty queries or permission errors
    if (!failedQuery?.trim()) return;
    // One correction per failed query: a submission failure and its job
    // failure must not both ask the model for the same fix.
    const correctionKey = `${errorCode}\u0000${failedQuery}`;
    if (correctionInFlightRef.current === correctionKey) return;
    correctionInFlightRef.current = correctionKey;

    setIsCorrectingQuery(true);
    api.correctQuery({
      query: failedQuery,
      error_message: errorMsg,
      error_code: errorCode,
      field_suggestions: fieldSuggestions || [],
    }).then(result => {
      if (result.corrected_query) {
        // Merge AI suggestion into the existing error's suggestions
        setSearchError(prev => {
          if (!prev) return prev;
          const aiSuggestion = {
            description: result.explanation,
            replacement: result.corrected_query,
            // Flag when the correction couldn't be validated (NAN-1496) so the
            // UI can surface an "unverified" badge.
            unverified: result.validated === false,
          };
          const existing = prev.details?.suggestions || [];
          return {
            ...prev,
            details: {
              ...prev.details,
              suggestions: [aiSuggestion, ...existing],
            } as ParseErrorDetails,
          };
        });
      }
    }).catch((err: unknown) => {
      // 409 ai_provider_not_configured means the platform has no enabled AI
      // provider for this tenant — expected, not an error worth the console.
      if (!(err instanceof ApiClientError && err.status === 409)) {
        console.error('[QueryCorrection] Failed:', err);
      }
    }).finally(() => {
      if (correctionInFlightRef.current === correctionKey) correctionInFlightRef.current = null;
      setIsCorrectingQuery(false);
    });
  }, [capabilities.queryCorrection]);

  // Request AI best practices review after a successful complex query
  const requestQueryReview = useCallback((successfulQuery: string) => {
    // POST /api/melod/review-query — gated on the AI capability (which, on a
    // hosted-shared tenant, already folds in the platform provider state).
    if (!capabilities.melod) return;
    if (!successfulQuery?.trim()) return;
    // Only review piped queries (not SQL mode)
    if (queryMode === 'sql') return;
    // Count pipes to determine complexity — skip simple queries
    const pipeCount = successfulQuery.split('|').length - 1;
    if (pipeCount < 2) return;

    setIsReviewingQuery(true);
    setQueryReviewSuggestions([]);
    api.reviewQuery({ query: successfulQuery })
      .then(result => {
        if (result.suggestions?.length > 0) {
          setQueryReviewSuggestions(result.suggestions);
        }
      })
      .catch((err: unknown) => {
        console.error('[QueryReview] Failed:', err);
      })
      .finally(() => {
        setIsReviewingQuery(false);
      });
  }, [queryMode, capabilities.melod]);

  // Detect if query looks like natural language (for AI suggestion pill)
  // Strategy: detect structured queries (finite syntax) and treat everything else as natural language
  const looksLikeNaturalLanguage = useCallback((q: string): boolean => {
    const trimmed = q.trim();
    if (trimmed.length < 10) return false; // Too short to be meaningful

    // Must have spaces (multiple words) to be natural language
    if (!trimmed.includes(' ')) return false;

    const lower = trimmed.toLowerCase();

    // --- Detect structured queries (nPL, SQL, field filters) ---

    // SQL keywords
    if (/^(select|with|insert|update|delete)\b/.test(lower)) return false;

    // nPL pipe syntax: anything with | is a piped query
    if (trimmed.includes('|')) return false;

    // Field=value patterns at start of query (src_ip="1.2.3.4", status=500, user!="admin")
    if (/^\w+\s*[=!<>]=?\s*(".*?"|\d+|'.*?'|\S+)/.test(trimmed)) return false;

    // Field:value filter syntax
    if (/^\w+:/.test(trimmed)) return false;

    // Starts with nPL command keywords (stats, sort, eval, etc.)
    // Note: 'where' excluded — only valid after a pipe, starting with "where" is NL
    if (/^(stats|sort|head|tail|table|timechart|eval|dedup|rename|rex|fields|top|rare|lookup|spath)\b/.test(lower)) return false;

    // Quoted exact search phrases ("failed login attempt")
    if (/^"[^"]*"$/.test(trimmed)) return false;

    // Boolean keyword search (error AND login, NOT admin)
    if (/\b(AND|OR|NOT)\b/.test(trimmed)) return false;

    // Regex search patterns (/pattern/)
    if (/^\/.*\/$/.test(trimmed)) return false;

    // Single search term with wildcard (error*, *admin*)
    if (/^\S+\*|\*\S+$/.test(trimmed) && !trimmed.includes(' ')) return false;

    const words = lower.split(/\s+/);
    const firstWord = words[0];

    // 1. First word is a command/question verb → almost certainly natural language
    //    Keyword searches never start with imperative verbs directed at the system
    const commandVerbs = new Set([
      'show', 'find', 'list', 'get', 'give', 'tell', 'display', 'search', 'look',
      'review', 'check', 'investigate', 'analyze', 'analyse', 'examine', 'inspect',
      'summarize', 'summarise', 'explain', 'describe', 'identify', 'detect', 'locate',
      'count', 'compare', 'correlate', 'monitor', 'track', 'verify', 'confirm',
      'what', 'where', 'when', 'how', 'why', 'which', 'who',
      'are', 'is', 'was', 'were', 'do', 'does', 'did',
      'can', 'could', 'would', 'should',
      'i', 'any', 'have', 'has',
    ]);
    if (commandVerbs.has(firstWord)) return true;

    // 2. Contains functional/structural words (articles, prepositions, pronouns)
    //    These are the glue of sentences and don't appear in keyword searches
    const structuralWords = new Set([
      'the', 'a', 'an', 'to', 'for', 'of', 'with', 'from', 'by', 'about',
      'over', 'between', 'through', 'during', 'after', 'before', 'since',
      'my', 'me', 'i', 'our', 'we', 'their', 'its',
      'any', 'every', 'each', 'all', 'most',
    ]);
    const hasStructuralWord = words.some(w => structuralWords.has(w));

    return hasStructuralWord;
  }, []);

  // AI Assistant state
  const [aiResponse, setAiResponse] = useState<string | null>(null);
  const [aiError, setAiError] = useState<string | null>(null);
  const [showAiThinking, setShowAiThinking] = useState(false);
  const [aiGeneratedSql, setAiGeneratedSql] = useState<string | null>(null);
  const [aiFieldsUsed, setAiFieldsUsed] = useState<string[]>([]);
  const [aiComplexity, setAiComplexity] = useState<string | null>(null);
  const [aiSuggestedTimeRange, setAiSuggestedTimeRange] = useState<string | null>(null);
  const [showAiDetails, setShowAiDetails] = useState(false);
  const [aiReasoningSteps, setAiReasoningSteps] = useState<Array<{
    step_type: string;
    title: string;
    description: string;
    details?: Record<string, unknown>;
  }>>([]);

  // AI conversation history for iterative refinement
  const [aiConversationHistory, setAiConversationHistory] = useState<Array<{
    user_message: string;
    generated_query: string;
    result_summary?: string;
    key_context?: string;
  }>>([]);
  const [refinementQuery, setRefinementQuery] = useState('');
  const isAiSettingQueryRef = useRef(false); // Track when AI sets query (vs user typing)

  // Chart drag selection state
  const [refAreaLeft, setRefAreaLeft] = useState<string | number | null>(null);
  const [refAreaRight, setRefAreaRight] = useState<string | number | null>(null);
  const isDraggingRef = useRef(false); // Track if user is dragging vs clicking
  
  // Track if we're restoring from browser history (to avoid pushing new entries)
  const isRestoringFromHistory = useRef(false);
  
  const abortControllerRef = useRef<AbortController | null>(null);
  const currentRequestIdRef = useRef<string | null>(null);
  // NAN-3883: the identity and start time of the in-flight non-append run.
  // Only a run still in flight is joined: once it settles (rows, error or
  // cancel) the same search is a deliberate re-run.
  const lastRunStartRef = useRef<SearchRunStart | null>(null);
  useEffect(() => {
    if (!isSearching) lastRunStartRef.current = null;
  }, [isSearching]);
  // NAN-3299: the bounds the current run resolved its time range to. Every
  // request of the run, its later pages and the URL it writes reuse them, so a
  // relative pick is resolved once per run (see search-run-scope.ts).
  const runScopeRef = useRef<SearchRunScope | null>(null);
  const [runScope, setRunScope] = useState<SearchRunScope | null>(null);
  // Aborts the run's companion requests (field stats) when a newer run starts,
  // the search is stopped, or the page unmounts — so a superseded run stops
  // holding per-user admission permits. Unlike `abortControllerRef`, a page
  // flip within the same run does not abort it.
  const runControllerRef = useRef<AbortController | null>(null);
  const beginRunScope = useCallback((range: TimeRangeValue) => {
    runControllerRef.current?.abort();
    runControllerRef.current = new AbortController();
    const scope: SearchRunScope = { timeRange: range, range: toApiTimeRange(range) };
    runScopeRef.current = scope;
    setRunScope(scope);
    return scope.range;
  }, []);
  const prevTimeRangeRef = useRef(timeRange);

  // Hooks
  const { mutate: search } = useSearch();
  const { mutate: searchSql } = useSearchSql();
  const { mutate: explainQuery, loading: explaining } = useExplainQuery();
  const { mutate: fetchFieldStats, loading: fieldStatsLoading } = useFieldStats();
  const { mutate: fetchSearchFieldValues } = useSearchFieldValues();

  // NAN-1427: refetch field stats over the FULL column inventory (no
  // `columns` restriction) when the analyst asks to index all fields.
  const loadAllFieldStats = useCallback(() => {
    const req = lastFieldStatsRequestRef.current;
    if (!req) return;
    // `reduced` stays true until the full stats land — the panel's teaser
    // derives its in-flight state from (reduced && isLoadingMore), and a
    // failure simply leaves the affordance in place.
    fetchFieldStats({ ...req, signal: runControllerRef.current?.signal })
      .then(fieldStatsResponse => {
        if (fieldStatsResponse.fields && fieldStatsResponse.fields.length > 0) {
          setServerFieldStats(fieldStatsResponse.fields);
          setFieldStatsReduced(false);
        }
      })
      .catch(err => {
        console.warn('Failed to fetch full field stats:', err);
      });
  }, [fetchFieldStats]);
  // GET /api/search/saved + /api/search/saved/shared — tenant-scoped on the
  // shared profile (the shared dashboards module).
  const { data: savedSearches, refetch: refetchSaved } = useSavedSearches();
  const { data: sharedSearches } = useSharedSearches();

  // Read pinned search IDs from localStorage (synced with SearchHub)
  const [pinnedSearchIds, setPinnedSearchIds] = useState<string[]>(() => {
    try {
      const stored = localStorage.getItem('nanosiem_pinned_searches');
      return stored ? JSON.parse(stored) : [];
    } catch {
      return [];
    }
  });

  // Listen for localStorage changes from SearchHub
  useEffect(() => {
    const handleStorageChange = (e: StorageEvent) => {
      if (e.key === 'nanosiem_pinned_searches') {
        try {
          setPinnedSearchIds(e.newValue ? JSON.parse(e.newValue) : []);
        } catch {
          setPinnedSearchIds([]);
        }
      }
    };
    window.addEventListener('storage', handleStorageChange);
    return () => window.removeEventListener('storage', handleStorageChange);
  }, []);
  const { mutate: createSavedSearch, loading: saving } = useCreateSavedSearch();
  const { mutate: _deleteSavedSearch } = useDeleteSavedSearch();
  const { mutate: _shareSavedSearch } = useShareSavedSearch();
  const { mutate: createSharedSearch } = useCreateSharedSearch();
  const { mutate: getSharedSearch } = useGetSharedSearch();
  const buildQueryJob = useMelodJob<MelodApiResponse>();
  const aiLoading = buildQueryJob.loading;
  // GET /api/settings/ai-availability — served on every profile.
  const { data: melodStatus } = useMelodStatus({ skip: !capabilities.melod });
  const [aiSessionId, setAiSessionId] = useState<string | undefined>(
    () => sessionStorage.getItem('melod-session-search') ?? undefined
  );
  const { mutate: storeQueryExplanation } = useStoreQueryExplanation();
  const { mutate: getQueryExplanation } = useGetQueryExplanation();

  const {
    searchHistory,
    historyEnabled,
    toggleHistoryEnabled,
    clearSearchHistory,
    addToSearchHistory,
    refreshHistory,
  } = useSearchHistory(); // /api/search/history* — tenant-scoped on shared

  // Notebook capture for auto-documenting investigations
  const { captureSearch, isActive: notebookActive, addEntityToNotebook, addEntitiesToNotebook } = useNotebookCapture();

  const canSave = hasPermission('search:save');
  const canShare = hasPermission('search:share');
  const canSql = hasPermission('search:sql');
  const canRawSql = canSql && searchSurface.rawSql && !isOcsf;

  useEffect(() => {
    // Keep the empty search console aligned with the user's preferred mode.
    // Once the user has query text, preserve the live mode and let query parsing drive it.
    if (query.trim()) return;
    setQueryMode(userQueryMode === 'advanced' && canRawSql ? 'sql' : 'piped');
  }, [query, userQueryMode, canRawSql]);

  // Debounced effect to show/hide AI suggestion pill
  useEffect(() => {
    // Clear any pending timeout
    if (aiSuggestionTimeoutRef.current) {
      clearTimeout(aiSuggestionTimeoutRef.current);
    }

    // Only show if meloD is connected
    if (!melodStatus?.connected) {
      setShowAiSuggestion(false);
      return;
    }

    // Debounce the check
    aiSuggestionTimeoutRef.current = setTimeout(() => {
      const shouldShow = looksLikeNaturalLanguage(query);
      setShowAiSuggestion(shouldShow);
    }, 400);

    return () => {
      if (aiSuggestionTimeoutRef.current) {
        clearTimeout(aiSuggestionTimeoutRef.current);
      }
    };
  }, [query, melodStatus?.connected, looksLikeNaturalLanguage]);

  // URL management - pushHistory=true creates a new browser history entry (for back button)
  const updateUrl = useCallback((q: string, mode: 'piped' | 'sql', time: TimeRangeValue, shortId?: string, pushHistory: boolean = false, prevalence?: number, ds?: import('@/lib/api/types').SearchDataset) => {
    const params = new URLSearchParams();
    if (shortId) {
      params.set('s', shortId);
      prevUrlRef.current = params.toString();
      setSearchParams(params, { replace: !pushHistory });
      return;
    }
    if (q) params.set('q', searchQueryForUrl(q));
    if (mode !== 'piped') params.set('mode', mode);
    // NAN-3884: a relative pick stays relative (`time=`); a fixed range
    // carries its bounds. Reload/back-nav then shows the label the analyst
    // picked, not the absolute times it happened to resolve to.
    writeTimeRangeParams(params, time);
    // Add prevalence filter to URL if not default (100 = show all)
    if (prevalence !== undefined && prevalence < 100) {
      params.set('prevalence', prevalence.toString());
    }
    // NAN-1825: keep the dataset in the URL for non-logs searches so refresh /
    // back-nav / copied links reproduce the spans/metrics/risk search instead
    // of silently falling back to logs.
    if (ds && ds !== 'logs') {
      params.set('dataset', ds);
    }
    // NAN-3299: this is the page's own write, not back/forward navigation. The
    // URL-sync effect read the relative -> absolute rewrite as a new time range
    // and re-ran the search (a second /api/search + /histogram per run).
    prevUrlRef.current = params.toString();
    setSearchParams(params, { replace: !pushHistory });
  }, [setSearchParams]);

  // Share URL functions
  const getShareableUrl = useCallback(() => {
    const params = new URLSearchParams();
    if (query) params.set('q', searchQueryForUrl(query));
    if (queryMode !== 'piped') params.set('mode', queryMode);
    // NAN-3884: a shared link to a relative range re-resolves for the
    // recipient, like a stored short link (time_range_preset) already does.
    writeTimeRangeParams(params, timeRange);
    if (prevalenceMax < 100) {
      params.set('prevalence', prevalenceMax.toString());
    }
    // NAN-1825: shared links must carry the dataset, or a copied risk/spans/
    // metrics search runs against logs for the recipient.
    if (dataset !== 'logs') {
      params.set('dataset', dataset);
    }
    const baseUrl = window.location.origin + window.location.pathname;
    return params.toString() ? `${baseUrl}?${params.toString()}` : baseUrl;
  }, [query, queryMode, timeRange, prevalenceMax, dataset]);

  const copyShareableUrl = useCallback(async () => {
    const url = getShareableUrl();
    try {
      await navigator.clipboard.writeText(url);
      setCopiedUrl(true);
      setTimeout(() => setCopiedUrl(false), 2000);
    } catch {
      const textArea = document.createElement('textarea');
      textArea.value = url;
      document.body.appendChild(textArea);
      textArea.select();
      document.execCommand('copy');
      document.body.removeChild(textArea);
      setCopiedUrl(true);
      setTimeout(() => setCopiedUrl(false), 2000);
    }
  }, [getShareableUrl]);

  const createAndCopyShortUrl = useCallback(async () => {
    if (!searchSurface.storedShortLinks) return;
    if (!query?.trim()) return;
    setIsCreatingShortUrl(true);
    try {
      const result = await createSharedSearch({
        query: searchQueryForUrl(query),
        query_mode: queryMode,
        time_range_type: timeRange.type,
        time_range_preset: timeRange.type === 'preset' ? timeRange.preset : undefined,
        time_range_start: timeRange.type === 'custom' && timeRange.start ? timeRange.start.toISOString() : undefined,
        time_range_end: timeRange.type === 'custom' && timeRange.end ? timeRange.end.toISOString() : undefined,
      });
      setShortUrlId(result.id);
      const shortUrl = `${window.location.origin}/search?s=${result.id}`;
      await navigator.clipboard.writeText(shortUrl);
      setCopiedUrl(true);
      setTimeout(() => setCopiedUrl(false), 2000);
    } catch (err) {
      setSearchError(handleError(err, 'Failed to create short URL'));
    } finally {
      setIsCreatingShortUrl(false);
    }
  }, [searchSurface.storedShortLinks, query, queryMode, timeRange, createSharedSearch]);

  // Clear async job state
  const clearAsyncJob = useCallback(() => {
    if (asyncJobPollingRef.current) {
      clearInterval(asyncJobPollingRef.current);
      asyncJobPollingRef.current = null;
    }
    setAsyncJobId(null);
    setAsyncJobStatus(null);
    setAsyncJobProgress(null);
    setQueuePosition(null);
    setEstimatedWait(null);
  }, []);

  // Cancel async job
  const handleCancelAsyncJob = useCallback(() => {
    if (artifactRef.current) {
      artifactRef.current = null;
      abortControllerRef.current?.abort();
      currentRequestIdRef.current = null;
    } else if (!asyncJobId) {
      // NAN-3229: no job yet, so the search request itself is still in flight
      // (it may escalate to a job at the server deadline). Stop it the way the
      // Stop button does: abort the transport and cancel its request id.
      if (sseControllerRef.current) {
        sseControllerRef.current.abort();
        sseControllerRef.current = null;
        setIsStreamingResults(false);
      }
      abortControllerRef.current?.abort();
      abortControllerRef.current = null;
      runControllerRef.current?.abort();
      if (currentRequestIdRef.current) {
        api.cancelSearch(currentRequestIdRef.current).catch(() => {});
        currentRequestIdRef.current = null;
      }
      setIsSearching(false);
    }
    if (asyncJobId) {
      api.cancelSearchJob(asyncJobId).catch(() => {});
      clearAsyncJob();
      setIsSearching(false);
    }
  }, [asyncJobId, clearAsyncJob]);

  // Cleanup polling, SSE, and tail on unmount
  useEffect(() => {
    return () => {
      artifactRef.current = null;
      abortControllerRef.current?.abort();
      runControllerRef.current?.abort();
      if (asyncJobPollingRef.current) {
        clearInterval(asyncJobPollingRef.current);
      }
      if (sseControllerRef.current) {
        sseControllerRef.current.abort();
      }
      if (tailTimerRef.current) {
        clearInterval(tailTimerRef.current);
      }
      tailFollowControllerRef.current?.abort();
      if (tailRetryTimerRef.current) clearTimeout(tailRetryTimerRef.current);
    };
  }, []);

  // Keep ref in sync with isSearching so the tail timer callback reads fresh value
  useEffect(() => {
    tailSearchingSinceRef.current = isSearching ? (tailSearchingSinceRef.current || Date.now()) : 0;
    // NAN-3273: a run that ended (failed, cancelled) without installing a
    // timeline must not keep showing the held one. A split companion still
    // in flight installs (or fails, below) on its own.
    const split = splitHistogramRef.current;
    const companionPending = split !== null && split.requestId === currentRequestIdRef.current
      && !split.published && split.histogram === undefined;
    if (!isSearching && !companionPending) setTimelineHold(null);
  }, [isSearching]);

  // Follow shared cell streams; retain polling for gen1 and dedicated tenants.
  useEffect(() => {
    if (tailTimerRef.current) {
      clearInterval(tailTimerRef.current);
      tailTimerRef.current = null;
    }

    if (!tailActive || !query?.trim()) return;

    // NAN-2551: re-arm the tail against whatever is on screen right now, then
    // let each tick prepend arrivals. The tick body lives behind a ref so this
    // effect keeps its minimal deps and the timer is never torn down mid-run.
    tailWatermarkRef.current = 0;
    // The histogram covers the whole executed query window, including events
    // newer than the displayed page. Using the newest row double counts those
    // events when the tail's overlap delivers them. Preserve later anchors.
    const histogramEndMs = new Date(resolveRunTimeRange(runScopeRef.current, timeRange).end).getTime();
    tailHistogramCutoffRef.current = tailHistogramCutoff(
      tailHistogramCutoffRef.current,
      histogramEndMs,
    );
    const prependEligible = tailPrependEligible(queryMode, isAggregateQuery, displayType);
    // NAN-3263: the first tick re-anchors the count on the rolling window (the
    // histogram on screen may be from a search that ran long before arming).
    tailReanchorRef.current.lastRequestedMs = 0;

    // NAN-3244: one supervisor tick per interval. While the follow stream is
    // open it covers the tail; whenever it is not (never opened, ended,
    // failed), every tick polls, and an ended follow is reconnected with
    // backoff. A follow end also runs a tick at once (see startTailFollow).
    const followEligible = Boolean(tenantPlan) && prependEligible && dataset === 'logs';
    tailSupervisorRef.current = tailSupervisor();
    const tick = () => {
      const action = tailSupervisorTick(tailSupervisorRef.current, {
        nowMs: Date.now(),
        followEligible,
        intervalMs: tailInterval,
        pollStartedAtMs: tailPollStartedAtRef.current,
        searchingSinceMs: tailSearchingSinceRef.current,
      });
      if (action.reconnect) {
        tailFollowControllerRef.current?.abort();
        startTailFollowRef.current();
      }
      if (action.poll) runTailRefreshRef.current();
      // NAN-3254: slide the chart with the clock even on a quiet source.
      if (prependEligible) advanceTailTimelineRef.current([]);
      // NAN-3263: and periodically re-read the true rolling window's count.
      if (prependEligible) reanchorTailTimelineRef.current(tailInterval);
    };
    tailTickRef.current = tick;
    if (followEligible) startTailFollowRef.current();
    tailTimerRef.current = setInterval(tick, tailInterval);
    // NAN-3264: a follow whose connection is open but which has sent no rows
    // and no heartbeat for TAIL_FOLLOW_STALL_MS is dead. Checked on its own
    // short timer, so a long tick interval cannot stretch the detection.
    const stallWatch = followEligible
      ? setInterval(() => {
          const nowMs = Date.now();
          const sup = tailSupervisorRef.current;
          if (!tailFollowStalled(sup, nowMs)) return;
          tailFollowControllerRef.current?.abort();
          tailFollowControllerRef.current = null;
          tailSupervisorRef.current = tailFollowEnded(sup, sup.generation, 'error', nowMs);
          tailTickRef.current();
          scheduleTailRetryRef.current(nowMs);
        }, TAIL_FOLLOW_STALL_CHECK_MS)
      : null;

    return () => {
      if (tailTimerRef.current) {
        clearInterval(tailTimerRef.current);
        tailTimerRef.current = null;
      }
      if (stallWatch) clearInterval(stallWatch);
      tailTickRef.current = () => {};
      if (tailRetryTimerRef.current) {
        clearTimeout(tailRetryTimerRef.current);
        tailRetryTimerRef.current = null;
      }
      tailSupervisorRef.current = tailSupervisor();
      tailFollowControllerRef.current?.abort();
      tailFollowControllerRef.current = null;
      tailReanchorRef.current.controller?.abort();
      tailReanchorRef.current.controller = null;
    };
  }, [tailActive, tailInterval, tenantPlan, queryMode, isAggregateQuery, displayType, dataset,
      query, executedQuery, timeRange, prevalenceMax]);

  // Auto-stop tail on query change
  const prevQueryRef = useRef(query);
  useEffect(() => {
    if (prevQueryRef.current !== query && tailActive) {
      setTailActive(false);
    }
    // NAN-2836: the "stopped for a fixed range" note belongs to the old query.
    if (prevQueryRef.current !== query) setTailStoppedForRange(false);
    prevQueryRef.current = query;
  }, [query]); // eslint-disable-line react-hooks/exhaustive-deps

  // Auto-stop tail on search error
  useEffect(() => {
    if (searchError && tailActive) setTailActive(false);
  }, [searchError]); // eslint-disable-line react-hooks/exhaustive-deps

  // Process async job results when completed
  const processAsyncJobResult = useCallback((
    response: import('@/lib/api/types').SearchResponse,
    currentQuery: string,
    currentTimeRange: TimeRangeValue,
    currentMode: 'piped' | 'sql',
    isAggregate: boolean,
    // NAN-1825: dataset the job's search actually targeted. Falls back to the
    // live selector state for callers that don't know it (URL job loads).
    jobDataset?: import('@/lib/api/types').SearchDataset,
    resultOffset: number = 0,
    pageContext?: AsyncSearchPage,
  ) => {
    const effectiveDataset = jobDataset ?? dataset;
    const results: SearchResult[] = (response.results || [])
      .filter((r: unknown) => r != null && typeof r === 'object')
      .map((r: Record<string, unknown>, i: number) => ({
        id: `result-${(pageContext?.offset ?? 0) + resultOffset + i}`,
        timestamp: eventTimestamp(r),
        source: eventSource(r),
        fields: (r && typeof r === 'object') ? r : {},
      }));

    const pageState = mergeAsyncSearchPage(asyncPageStateRef.current, results, response.total_count || results.length,
      pageContext ?? { append: false, offset: resultOffset, page: 1, pageSize: results.length });
    if (pageContext) {
      pageState.complete = !(response.has_more ?? (response.total_count_exact
        ? pageContext.offset + results.length < response.total_count
        : response.total_count > pageContext.offset + results.length || response.results.length >= pageContext.pageSize));
    }
    asyncPageStateRef.current = pageState;
    setSearchResults(pageState.results);
    setPagingComplete(pageState.complete);
    if (pageContext) setCurrentPage(pageState.currentPage);

    // Only the initial run is a notebook search. Paging reuses its metadata.
    captureInitialSearchPage(pageContext, () => {
      const apiTime = resolveRunTimeRange(runScopeRef.current, currentTimeRange);
      captureSearch(currentQuery, currentMode, response.total_count || results.length,
        response.execution_time_ms, apiTime.start, apiTime.end);
    });

    // Shared Search cannot safely reuse browser result rows after an authority
    // revocation because the browser does not own the grant-authority revision.
    const cacheKey = searchSurface.browserResultCache
      ? buildCacheKey(currentQuery, currentTimeRange, currentMode, effectiveDataset)
      : null;
    const split = splitHistogramRef.current;
    const splitActive = !pageContext?.append && split !== null && split.requestId === currentRequestIdRef.current;
    if (splitActive) {
      split.rowsIn = true;
      setSplitTiming({ firstRowsMs: Math.round(performance.now() - split.startedAt) });
      if (split.total !== undefined) {
        asyncPageStateRef.current = {
          ...asyncPageStateRef.current,
          totalCount: split.total,
        };
        setPagingComplete(asyncPageStateRef.current.complete);
      }
    }
    if (!pageContext?.append) {
      setExecutedQuery(currentQuery);
      setTotalCount(splitActive && split.total !== undefined ? split.total : (response.total_count || results.length));
      setTotalCountExact(splitActive && split.total !== undefined ? true : (response.total_count_exact ?? false));
      if (response.generated_sql) setGeneratedSql(response.generated_sql);
      setCompleteness(response.completeness);
      const shownMs = searchDisplayTimeMs(response);
      if (shownMs !== undefined) setExecutionTimeMs(shownMs);
      if (response.display_type) {
        setDisplayType(response.display_type);
        setTablePage(0);
      }
      if (response.column_order) setColumnOrder(response.column_order);
      const histData = response.histogram && response.histogram.length > 0
        ? response.histogram.map(bucket => ({ time: bucket.time, count: bucket.count }))
        : [];
      // Always update histogram (even if empty) to clear stale data from previous searches,
      // unless this search's timeline comes from its own request (NAN-3093).
      if (!splitActive) setHistogramData(histData);

      if (cacheKey) {
        const cacheEntry: CachedSearchResult = {
          results,
          histogramData: histData,
          serverFieldStats: null,
          fieldStatsReduced: null,
          totalCount: response.total_count || results.length,
          totalCountExact: response.total_count_exact ?? false,
          executionTimeMs: searchDisplayTimeMs(response) ?? null,
          completeness: response.completeness,
          displayType: response.display_type,
          columnOrder: response.column_order,
          generatedSql: response.generated_sql || null,
          costScore: response.cost_score ?? null,
          executedQuery: currentQuery,
          isAggregateQuery: isAggregate,
          peakRowsScanned: 0,
          cachedAt: Date.now(),
        };
        searchResultCache.set(cacheKey, cacheEntry);
        if (searchResultCache.size > 10) {
          const now = Date.now();
          for (const [k, v] of searchResultCache) {
            if (now - v.cachedAt > CACHE_TTL_MS) searchResultCache.delete(k);
          }
        }
      }

    }

    // NAN-2550: "this count is a lower bound" is no longer a warning — it rides
    // on `total_count_exact` and renders inline next to the count. This filter
    // only suppresses the banner from a server that predates that change, and
    // can be deleted once no pre-NAN-2550 search service is in rotation.
    const warnings = response.warnings?.filter(w => w.code !== 'LAKE_PAGE_BOUND_COUNT');
    // Handle query warnings
    if (warnings && warnings.length > 0) {
      const errorWarning = warnings.find(w => w.severity === 'error');
      const warningWarning = warnings.find(w => w.severity === 'warning');
      const mainWarning = errorWarning || warningWarning || warnings[0];

      setSearchError({
        code: mainWarning.code,
        message: mainWarning.message,
        warningSeverity: mainWarning.severity as 'info' | 'warning' | 'error',
        details: {
          position: 0,
          line: 1,
          column: 1,
          expected: [],
          suggestions: mainWarning.suggestion ? [{
            description: mainWarning.suggestion,
            replacement: ''
          }] : [],
          formatted: mainWarning.message,
          impact: mainWarning.impact
        }
      });
    }

    if (pageContext?.append) return;

    // Request AI best practices review for complex queries
    if (!response.warnings?.length && currentMode === 'piped') {
      requestQueryReview(currentQuery);
    }

    // Fetch field stats asynchronously (for non-aggregate piped queries)
    if (!isAggregate && currentMode === 'piped') {
      const apiTime = resolveRunTimeRange(runScopeRef.current, currentTimeRange);
      // NAN-1427/1428: reduced column set + request_id for cancel coverage
      const fsRequest = {
        query: currentQuery,
        start: apiTime.start,
        end: apiTime.end,
        request_id: currentRequestIdRef.current ?? undefined,
        dataset: effectiveDataset, // NAN-1559: stats must enumerate the same dataset the search targeted
      };
      lastFieldStatsRequestRef.current = fsRequest;
      // Preserve the established two-stage rail: paint Selected immediately,
      // then let the analyst explicitly fetch the remaining inventory into
      // Available. Lake table rows are intentionally slim, so treating a small
      // result count as a complete field inventory hides mapped OCSF leaves.
      setFieldStatsReduced(true);
      fetchFieldStats({ ...fsRequest, columns: collectFieldStatsColumns(results, isOcsf, promotedSchemaFields), signal: runControllerRef.current?.signal })
        .then(fieldStatsResponse => {
          setServerFieldStats(fieldStatsResponse.fields ?? []);
          setFieldStatsReduced(true);
          // Update cache entry with field stats
          const cached = cacheKey ? searchResultCache.get(cacheKey) : undefined;
          if (cached) {
            cached.serverFieldStats = fieldStatsResponse.fields ?? [];
            cached.fieldStatsReduced = true;
          }
        })
        .catch(err => {
          console.warn('Failed to fetch field stats:', err);
        });
    }

    // Update AI conversation history with result summary
    const resultCount = response.total_count || results.length;
    if (resultCount > 0) {
      setAiConversationHistory(prev => {
        if (prev.length === 0) return prev;
        const updated = [...prev];
        const lastIdx = updated.length - 1;
        const keyFields = results
          .slice(0, 3)
          .map(r => eventKeyContext(r as unknown as Record<string, unknown>, isOcsf))
          .filter(Boolean)
          .join(' | ');

        updated[lastIdx] = {
          ...updated[lastIdx],
          result_summary: `Found ${resultCount.toLocaleString()} events`,
          key_context: keyFields || undefined,
        };
        return updated;
      });
    }
  }, [fetchFieldStats, captureSearch, toApiTimeRange, requestQueryReview, dataset, isOcsf, promotedSchemaFields, searchSurface.browserResultCache]);

  /** Restore a typed product artifact through its real product view rather
   * than rendering the artifact envelope as ordinary log rows. */
  const processTypedDurableJobResult = useCallback((
    status: SearchJobStatus,
    page: SearchJobResultPage,
    fallbackQuery: string,
    fallbackTimeRange: TimeRangeValue,
  ): boolean => {
    if (status.task_kind === 'asset_v1') {
      const row = page.rows[0];
      const response = row?.response as import('@/lib/api/types').AssetEventsResponse | undefined;
      const identifierField = row?.identifier_field;
      const identifierValue = row?.identifier_value;
      const identities = row?.identities;
      if (
        page.total_rows !== 1
        || typeof identifierField !== 'string'
        || typeof identifierValue !== 'string'
        || !Array.isArray(identities)
        || !response?.total_count_exact
      ) {
        throw new Error('Durable Asset job returned an invalid typed result artifact');
      }
      const jobQuery = status.query || fallbackQuery;
      const apiRange = status.time_range || toApiTimeRange(fallbackTimeRange);
      const restoredRange: TimeRangeValue = {
        type: 'custom',
        start: new Date(apiRange.start),
        end: new Date(apiRange.end),
      };
      setLiveRun(false);
      setQuery(jobQuery);
      setTimeRange(restoredRange);
      setDurableResultCursor(null);
      processAsyncJobResult({
        results: [{
          _display_type: 'asset',
          _asset_profile: {
            primary_identifier: { field: identifierField, value: identifierValue },
            identities,
            first_seen: null,
            last_seen: null,
            reanchored: false,
            effective_time_range: null,
            storage_model: 'ocsf-1.9-iceberg',
          },
          _asset_events: [],
          _asset_pagination: response,
          _asset_durable_summary: response,
        }],
        total_count: 1,
        total_count_exact: true, // NAN-2550: synthesised locally; this count is the whole set.
        execution_time_ms: status.progress?.elapsed_ms ?? 0,
        fields: [],
        display_type: 'asset',
      }, jobQuery, restoredRange, 'piped', true, status.dataset);
      return true;
    }
    if (status.task_kind === 'asset_dossier_v1') {
      const row = page.rows[0];
      const response = row?.response as import('@/lib/api/types').AssetDossierResponse | undefined;
      const identifierField = row?.identifier_field;
      const identifierValue = row?.identifier_value;
      const identities = row?.identities;
      if (
        page.total_rows !== 1
        || row?.operation !== 'asset_dossier'
        || typeof identifierField !== 'string'
        || typeof identifierValue !== 'string'
        || !Array.isArray(identities)
        || !response?.identity
      ) {
        throw new Error('Durable Asset dossier returned an invalid typed result artifact');
      }
      const jobQuery = status.query || fallbackQuery;
      const apiRange = status.time_range || toApiTimeRange(fallbackTimeRange);
      const restoredRange: TimeRangeValue = {
        type: 'custom',
        start: new Date(apiRange.start),
        end: new Date(apiRange.end),
      };
      setLiveRun(false);
      setQuery(jobQuery);
      setTimeRange(restoredRange);
      setDurableResultCursor(null);
      processAsyncJobResult({
        results: [{
          _display_type: 'asset',
          _asset_profile: {
            primary_identifier: { field: identifierField, value: identifierValue },
            identities,
            first_seen: null,
            last_seen: null,
            reanchored: false,
            effective_time_range: null,
            storage_model: 'ocsf-1.9-iceberg',
          },
          _asset_events: [],
          _asset_pagination: { total_count: 0, offset: 0, limit: 200, has_more: false },
          _asset_durable_dossier: response,
        }],
        total_count: 1,
        total_count_exact: true, // NAN-2550: synthesised locally; this count is the whole set.
        execution_time_ms: status.progress?.elapsed_ms ?? 0,
        fields: [],
        display_type: 'asset',
      }, jobQuery, restoredRange, 'piped', true, status.dataset);
      return true;
    }
    if (status.task_kind === 'cloud_events_summary_v1') {
      const row = page.rows[0];
      const response = row?.response as import('@/lib/api/types').CloudEventsResponse | undefined;
      if (
        page.total_rows !== 1
        || row?.operation !== 'cloud_events_summary'
        || !response?.total_count_exact
        || !response.facets
      ) {
        throw new Error('Durable Cloud event summary returned an invalid typed result artifact');
      }
      const jobQuery = status.query || fallbackQuery || '| cloud';
      const apiRange = status.time_range || toApiTimeRange(fallbackTimeRange);
      const restoredRange: TimeRangeValue = {
        type: 'custom',
        start: new Date(apiRange.start),
        end: new Date(apiRange.end),
      };
      setLiveRun(false);
      setQuery(jobQuery);
      setTimeRange(restoredRange);
      setDurableResultCursor(null);
      processAsyncJobResult({
        results: [{
          _display_type: 'cloud',
          _cloud_group_by: 'service',
          _cloud_principal: null,
          _cloud_account: null,
          _cloud_query: typeof row.query === 'string' ? row.query : jobQuery,
          _cloud_show_mfa: true,
          _cloud_events: [],
          _cloud_pagination: response,
          _cloud_summary: response.facets,
          _cloud_resources: response.resources || [],
          _cloud_user_activity: response.user_activity || [],
          _storage_model: 'ocsf-1.9-iceberg',
        }],
        total_count: 1,
        total_count_exact: true, // NAN-2550: synthesised locally; this count is the whole set.
        execution_time_ms: status.progress?.elapsed_ms ?? 0,
        fields: [],
        display_type: 'cloud',
      }, jobQuery, restoredRange, 'piped', true, status.dataset);
      return true;
    }
    if (status.task_kind === 'cloud_overview_v1') {
      const row = page.rows[0];
      const response = row?.response as import('@/lib/api/types').CloudOverviewResponse | undefined;
      if (
        page.total_rows !== 1
        || row?.operation !== 'cloud_overview'
        || !response?.header
      ) {
        throw new Error('Durable Cloud job returned an invalid typed result artifact');
      }
      const jobQuery = status.query || fallbackQuery || '| cloud';
      const apiRange = status.time_range || toApiTimeRange(fallbackTimeRange);
      const restoredRange: TimeRangeValue = {
        type: 'custom',
        start: new Date(apiRange.start),
        end: new Date(apiRange.end),
      };
      setLiveRun(false);
      setQuery(jobQuery);
      setTimeRange(restoredRange);
      setDurableResultCursor(null);
      processAsyncJobResult({
        results: [{
          _display_type: 'cloud',
          _cloud_group_by: 'account',
          _cloud_principal: null,
          _cloud_account: typeof row.account === 'string' ? row.account : null,
          _cloud_query: 'class_uid=6003',
          _cloud_show_mfa: true,
          _cloud_durable_overview: response,
          _storage_model: 'ocsf-1.9-iceberg',
        }],
        total_count: 1,
        total_count_exact: true, // NAN-2550: synthesised locally; this count is the whole set.
        execution_time_ms: status.progress?.elapsed_ms ?? 0,
        fields: [],
        display_type: 'cloud',
      }, jobQuery, restoredRange, 'piped', true, status.dataset);
      return true;
    }
    if (status.task_kind === 'cloud_dossier_v1') {
      const row = page.rows[0];
      const response = row?.response as import('@/lib/api/types').CloudDossierResponse | undefined;
      const principal = row?.principal;
      if (
        page.total_rows !== 1
        || row?.operation !== 'cloud_dossier'
        || typeof principal !== 'string'
        || !response?.identity
      ) {
        throw new Error('Durable Cloud dossier returned an invalid typed result artifact');
      }
      const jobQuery = status.query || fallbackQuery || `| cloud principal="${principal}"`;
      const apiRange = status.time_range || toApiTimeRange(fallbackTimeRange);
      const restoredRange: TimeRangeValue = {
        type: 'custom',
        start: new Date(apiRange.start),
        end: new Date(apiRange.end),
      };
      setLiveRun(false);
      setQuery(jobQuery);
      setTimeRange(restoredRange);
      setDurableResultCursor(null);
      processAsyncJobResult({
        results: [{
          _display_type: 'cloud',
          _cloud_group_by: 'account',
          _cloud_principal: principal,
          _cloud_account: typeof row.account === 'string' ? row.account : null,
          _cloud_query: 'class_uid=6003',
          _cloud_show_mfa: true,
          _cloud_durable_dossier: response,
          _storage_model: 'ocsf-1.9-iceberg',
        }],
        total_count: 1,
        total_count_exact: true, // NAN-2550: synthesised locally; this count is the whole set.
        execution_time_ms: status.progress?.elapsed_ms ?? 0,
        fields: [],
        display_type: 'cloud',
      }, jobQuery, restoredRange, 'piped', true, status.dataset);
      return true;
    }
    if (status.task_kind === 'lateral_v1') {
      const row = page.rows[0];
      const response = row?.response as import('@/lib/api/types').SearchResponse | undefined;
      const range = response?.results?.[0]?._lateral_time_range as { start?: string; end?: string } | undefined;
      if (page.total_rows !== 1 || row?.operation !== 'lateral' || response?.display_type !== 'lateral'
        || !Array.isArray(response.results) || !range?.start || !range.end
        || !Number.isFinite(Date.parse(range.start)) || !Number.isFinite(Date.parse(range.end))
        || Date.parse(range.start) >= Date.parse(range.end)) {
        throw new Error('Durable Lateral job returned an invalid result artifact');
      }
      const jobQuery = status.query || fallbackQuery;
      const restoredRange: TimeRangeValue = { type: 'custom', start: new Date(range.start), end: new Date(range.end) };
      setLiveRun(false);
      setQuery(jobQuery);
      setTimeRange(restoredRange);
      prevTimeRangeRef.current = restoredRange;
      const params = new URLSearchParams({ q: jobQuery, start: range.start, end: range.end });
      if (status.dataset && status.dataset !== 'logs') params.set('dataset', status.dataset);
      prevUrlRef.current = params.toString();
      setSearchParams(params, { replace: true });
      setDurableResultCursor(null);
      processAsyncJobResult(response, jobQuery, restoredRange, 'piped', true, status.dataset);
      return true;
    }
    if (status.task_kind === 'baseline_v1') {
      // NAN-3078: a `| baseline` that could not finish interactively ran as a
      // durable job; its artifact is the baseline rows themselves. The job was
      // admitted over the whole lookback (its retention-bound contribution
      // range), so its stored range is not the analyst's window: keep the
      // current time picker.
      if (!page.rows.every(row => typeof row?.entity_type === 'string')) {
        throw new Error('Durable baseline job returned an invalid result artifact');
      }
      const jobQuery = status.query || fallbackQuery;
      setLiveRun(false);
      setQuery(jobQuery);
      setDurableResultCursor(null);
      processAsyncJobResult({
        results: page.rows,
        total_count: page.total_rows,
        total_count_exact: true, // NAN-2550: the job evaluated every dimension.
        execution_time_ms: status.progress?.elapsed_ms ?? 0,
        fields: [],
        display_type: 'baseline',
      }, jobQuery, fallbackTimeRange, 'piped', true, status.dataset);
      return true;
    }
    if (status.task_kind !== 'retro_v1') return false;
    const row = page.rows[0] as unknown as RetroResponse | undefined;
    if (page.total_rows !== 1 || !row || !row.submode || !row.axis) {
      throw new Error('Durable Retro job returned an invalid typed result artifact');
    }
    const jobQuery = status.query || fallbackQuery;
    const apiRange = status.time_range || toApiTimeRange(fallbackTimeRange);
    const restoredRange: TimeRangeValue = {
      type: 'custom',
      start: new Date(apiRange.start),
      end: new Date(apiRange.end),
    };
    primeDurableRetroResult(jobQuery, apiRange, row);
    setLiveRun(false);
    setQuery(jobQuery);
    setTimeRange(restoredRange);
    setDurableResultCursor(null);
    processAsyncJobResult({
      results: [{
        _display_type: 'retro',
        _retro_submode: row.submode,
        _retro_axis: row.axis,
        _retro_indicator: row.indicator?.value ?? null,
        _retro_feed: null,
        _retro_feed_arg: null,
      }],
      total_count: 1,
      total_count_exact: true, // NAN-2550: synthesised locally; this count is the whole set.
      execution_time_ms: status.progress?.elapsed_ms ?? 0,
      fields: [],
      display_type: 'retro',
    }, jobQuery, restoredRange, 'piped', true, status.dataset);
    return true;
  }, [processAsyncJobResult, setSearchParams]);

  // Start polling for async job results
  const startAsyncJobPolling = useCallback((
    jobId: string,
    currentQuery: string,
    currentTimeRange: TimeRangeValue,
    currentMode: 'piped' | 'sql',
    isAggregate: boolean,
    // NAN-1825: dataset the job's search targeted — forwarded to
    // processAsyncJobResult so results cache under the right dataset.
    jobDataset?: import('@/lib/api/types').SearchDataset,
    pageContext?: AsyncSearchPage,
  ) => {
    // Clear any existing polling interval to prevent leaks
    if (asyncJobPollingRef.current) {
      clearInterval(asyncJobPollingRef.current);
      asyncJobPollingRef.current = null;
    }

    const pollingStarted = Date.now();
    const maxPolls = 86_400; // Durable jobs may legitimately run for hours.
    let pollCount = 0;
    let inFlight = false;
    const pollingRequestId = currentRequestIdRef.current;

    let pollingTimer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      // Guard: if polling was cleared, don't continue
      if (asyncJobPollingRef.current !== pollingTimer || inFlight) return;
      inFlight = true;

      try {
        pollCount++;
        if (pollCount > maxPolls || Date.now() - pollingStarted >= 86_400_000) {
          clearAsyncJob();
          setIsSearching(false);
          setSearchError({ code: 'TIMEOUT', message: 'Search job polling timed out after 24 hours' });
          return;
        }

        const status = await api.getSearchJob(jobId, {
          isCancelled: () => asyncJobPollingRef.current !== pollingTimer || currentRequestIdRef.current !== pollingRequestId,
          onUnavailable: () => setSearchError({ code: AUTHORITY_UNAVAILABLE, message: AUTHORITY_NOTICE, warningSeverity: 'info' }),
          onRecovered: () => setSearchError(previous => previous?.code === AUTHORITY_UNAVAILABLE ? null : previous),
        });

        // Guard again after async call - polling might have been cleared while waiting
        if (asyncJobPollingRef.current !== pollingTimer || currentRequestIdRef.current !== pollingRequestId) return;

        setAsyncJobStatus(status.status);
        setAsyncJobProgress(status.progress || null);

        if (status.status === 'queued') {
          // Update queue position and estimated wait, continue polling
          setQueuePosition(status.queue_position ?? null);
          setEstimatedWait(status.estimated_wait_seconds ?? null);
        } else if (status.status === 'running') {
          // Clear queue state when transitioning to running
          setQueuePosition(null);
          setEstimatedWait(null);
        } else if (status.status === 'completed' && status.result) {
          clearAsyncJob();
          setDurableResultCursor(null);
          processAsyncJobResult(status.result, currentQuery, currentTimeRange, currentMode, isAggregate, jobDataset, 0, pageContext);
          setIsSearching(false);
          setHasSearched(true);
          if (!pageContext?.append) queryClient.invalidateQueries({ queryKey: ['search-jobs'] });
        } else if (status.status === 'completed' && status.durable_result) {
          if (status.task_kind === 'prevalence_export_v1') {
            clearAsyncJob();
            try {
              const download = await api.downloadSearchJob(jobId);
              saveDurableDownload(download.blob, download.filename);
              setHasSearched(true);
            } catch (caught) {
              setSearchError({
                code: 'JOB_DOWNLOAD_FAILED',
                message: caught instanceof Error ? caught.message : 'Prevalence export download failed',
              });
            }
            setIsSearching(false);
            if (!pageContext?.append) queryClient.invalidateQueries({ queryKey: ['search-jobs'] });
            return;
          }
          const page = status.durable_result.pages === 0
            ? { page: 0, pages: 0, page_rows: status.durable_result.page_rows, row_offset: 0, total_rows: 0, rows: [] }
            : await api.getSearchJobResultPage(jobId, 0);
          if (asyncJobPollingRef.current !== pollingTimer || currentRequestIdRef.current !== pollingRequestId) return;
          clearAsyncJob();
          if (processTypedDurableJobResult(status, page, currentQuery, currentTimeRange)) {
            clearAsyncJob();
            setIsSearching(false);
            setHasSearched(true);
            if (!pageContext?.append) queryClient.invalidateQueries({ queryKey: ['search-jobs'] });
            return;
          }
          processAsyncJobResult({
            results: page.rows,
            total_count: page.total_rows,
            total_count_exact: true, // NAN-2550: synthesised locally; this count is the whole set.
            execution_time_ms: status.progress?.elapsed_ms ?? 0,
            fields: [],
            warnings: durableResultWarnings(status.durable_result, page.pages),
          }, currentQuery, currentTimeRange, currentMode, isAggregate, jobDataset, page.row_offset, pageContext);
          setDurableResultCursor({
            jobId,
            pages: page.pages,
            pageRows: status.durable_result.page_rows,
            loadedPage: page.page,
            rowOffset: page.row_offset,
          });
          setIsSearching(false);
          setHasSearched(true);
          if (!pageContext?.append) queryClient.invalidateQueries({ queryKey: ['search-jobs'] });
        } else if (status.status === 'failed') {
          clearAsyncJob();
          setIsSearching(false);
          if (!pageContext?.append) queryClient.invalidateQueries({ queryKey: ['search-jobs'] });
          // Detect parse errors from async job failures (error message starts with "Parse error" or contains position info)
          const errorMsg = status.error || 'Search job failed';
          const isParseError = /^(Parse error|Query parse error|Unexpected|Expected)/.test(errorMsg);
          const errCode = isParseError ? 'PARSE_ERROR' : 'JOB_FAILED';
          setSearchError({ code: errCode, message: errorMsg });
          requestQueryCorrection(errCode, errorMsg, query);
        } else if (status.status === 'cancelled') {
          clearAsyncJob();
          setIsSearching(false);
          if (!pageContext?.append) queryClient.invalidateQueries({ queryKey: ['search-jobs'] });
        }
      } catch (err) {
        if (err instanceof Error && err.name === 'AbortError') return;
        if ((err as { status?: number })?.status === 403) {
          clearAsyncJob();
          setIsSearching(false);
          setSearchError(handleError(err, 'Search authority is no longer current'));
          return;
        }
        console.error('Error polling job status:', err);
        // Continue polling - job might still be running
      } finally {
        inFlight = false;
        if (asyncJobPollingRef.current === pollingTimer && currentRequestIdRef.current === pollingRequestId) {
          pollingTimer = setTimeout(poll, asyncSearchPollDelay(pollCount));
          asyncJobPollingRef.current = pollingTimer;
        }
      }
    };
    pollingTimer = setTimeout(poll, asyncSearchPollDelay(0));
    asyncJobPollingRef.current = pollingTimer;
  }, [clearAsyncJob, processAsyncJobResult, processTypedDurableJobResult, queryClient]);

  // Start streaming search via SSE (replaces async polling for better UX)
  const startStreamingSearch = useCallback((
    request: { query: string; time_range: import('@/lib/api/types').TimeRange; limit: number; offset: number; skip_field_stats: boolean; skip_histogram?: boolean; table_view?: boolean; dataset?: import('@/lib/api/types').SearchDataset },
    currentQuery: string,
    currentTimeRange: TimeRangeValue,
    currentMode: 'piped' | 'sql',
    isAggregate: boolean,
    bypassCache: boolean = false
  ) => {
    // Abort any previous SSE stream
    if (sseControllerRef.current) {
      sseControllerRef.current.abort();
      sseControllerRef.current = null;
    }

    setIsStreamingResults(true);
    let rowBatch: SearchResult[] = [];
    let rafPending = false;
    let cumulativeRows = 0;
    // Tracked locally so `onCompleted` can persist the peak with the cache
    // entry without racing React's async state flush.
    let streamedPeakRowsScanned = 0;

    // Capture metadata from onMetadata so onCompleted can use it in cache
    let streamedMetadata: {
      histogramData: Array<{ time: string; count: number }>;
      totalCount: number;
      totalCountExact: boolean;
      executionTimeMs: number | null;
      completeness?: EventCompleteness;
      displayType: import('@/lib/api/types').DisplayType | undefined;
      columnOrder: string[] | undefined;
      generatedSql: string | null;
      costScore: number | null;
    } = {
      histogramData: [],
      totalCount: 0,
      totalCountExact: true,
      executionTimeMs: null,
      displayType: undefined,
      columnOrder: undefined,
      generatedSql: null,
      costScore: null,
    };

    const flushRows = () => {
      if (rowBatch.length === 0) return;
      const batch = rowBatch;
      rowBatch = [];
      rafPending = false;
      setSearchResults(prev => [...prev, ...batch]);
    };

    const controller = api.searchStreamSSE(request, {
      onQueued: (data) => {
        setQueuePosition(data.queue_position);
        setEstimatedWait(data.estimated_wait_seconds);
      },
      onStarted: (data) => {
        setQueuePosition(null);
        setEstimatedWait(null);
        setAsyncJobStatus('running');
        if (data.job_id) {
          setAsyncJobId(data.job_id);
          queryClient.invalidateQueries({ queryKey: ['search-jobs'] });
        }
      },
      onProgress: (data) => {
        setAsyncJobProgress(data);
        const scanned = data.rows_scanned || 0;
        if (scanned > streamedPeakRowsScanned) {
          streamedPeakRowsScanned = scanned;
          setPeakRowsScanned(scanned);
        }
      },
      onRows: (data) => {
        const newRows = (data.rows || [])
          .filter((r: unknown) => r != null && typeof r === 'object')
          .map((r: Record<string, unknown>, i: number) => ({
            id: `result-${cumulativeRows + i}`,
            timestamp: eventTimestamp(r),
            source: eventSource(r),
            fields: r,
          }));
        cumulativeRows += newRows.length;
        rowBatch.push(...newRows);

        // RAF-batched flush to avoid excessive re-renders
        if (!rafPending) {
          rafPending = true;
          requestAnimationFrame(flushRows);
        }
      },
      onMetadata: (data) => {
        setTotalCount(data.total_count);
        setTotalCountExact(data.total_count_exact ?? false);
        if (data.generated_sql) setGeneratedSql(data.generated_sql);
        setCompleteness(data.completeness);
        if (data.execution_time_ms !== undefined) setExecutionTimeMs(data.execution_time_ms);
        if (data.display_type) {
          setDisplayType(data.display_type);
          setTablePage(0);
        }
        if (data.column_order) setColumnOrder(data.column_order);
        const histData = data.histogram && data.histogram.length > 0
          ? data.histogram.map(b => ({ time: b.time, count: b.count }))
          : [];
        // Always update histogram (even if empty) to clear stale data from previous searches
        setHistogramData(histData);

        // Capture for cache entry in onCompleted
        streamedMetadata = {
          histogramData: histData,
          totalCount: data.total_count,
          totalCountExact: data.total_count_exact ?? false,
          executionTimeMs: data.execution_time_ms ?? null,
          completeness: data.completeness,
          displayType: data.display_type,
          columnOrder: data.column_order,
          generatedSql: data.generated_sql ?? null,
          costScore: data.cost_score ?? null,
        };
        // Handle warnings. NAN-2550: legacy-peer compat only — a pre-NAN-2550
        // search service still pushes the lower-bound fact as a warning.
        // Exactness now rides on `total_count_exact`.
        const streamWarnings = data.warnings?.filter(w => w.code !== 'LAKE_PAGE_BOUND_COUNT');
        if (streamWarnings && streamWarnings.length > 0) {
          const errorWarning = streamWarnings.find(w => w.severity === 'error');
          const warningWarning = streamWarnings.find(w => w.severity === 'warning');
          const mainWarning = errorWarning || warningWarning || streamWarnings[0];
          setSearchError({
            code: mainWarning.code,
            message: mainWarning.message,
            warningSeverity: mainWarning.severity as 'info' | 'warning' | 'error',
            details: {
              position: 0, line: 1, column: 1, expected: [],
              suggestions: mainWarning.suggestion ? [{ description: mainWarning.suggestion, replacement: '' }] : [],
              formatted: mainWarning.message,
              impact: mainWarning.impact
            }
          });
        }
      },
      onCompleted: (data) => {
        setPagingComplete(streamedMetadata.totalCountExact
          ? request.offset + cumulativeRows >= streamedMetadata.totalCount
          : streamedMetadata.totalCount <= request.offset + cumulativeRows && cumulativeRows < request.limit);
        // Flush any remaining buffered rows
        flushRows();
        setIsStreamingResults(false);
        setIsSearching(false);
        setHasSearched(true);
        clearAsyncJob();
        sseControllerRef.current = null;
        queryClient.invalidateQueries({ queryKey: ['search-jobs'] });

        // Cache results — keyed on the dataset the REQUEST ran against (not
        // the live selector state, which the user may have flipped mid-stream).
        const cacheKey = buildCacheKey(currentQuery, currentTimeRange, currentMode, request.dataset);
        // We need to read the final searchResults via a callback since state may not have flushed yet
        setSearchResults(finalResults => {
          if (searchSurface.browserResultCache) {
            const cacheEntry: CachedSearchResult = {
              results: finalResults,
              histogramData: streamedMetadata.histogramData,
              serverFieldStats: null,
              fieldStatsReduced: null,
              totalCount: streamedMetadata.totalCount || data.total_rows_delivered || finalResults.length,
              totalCountExact: streamedMetadata.totalCountExact,
              executionTimeMs: streamedMetadata.executionTimeMs,
              completeness: streamedMetadata.completeness,
              displayType: streamedMetadata.displayType,
              columnOrder: streamedMetadata.columnOrder,
              generatedSql: streamedMetadata.generatedSql,
              costScore: streamedMetadata.costScore,
              executedQuery: currentQuery,
              isAggregateQuery: isAggregate,
              peakRowsScanned: streamedPeakRowsScanned,
              cachedAt: Date.now(),
            };
            searchResultCache.set(cacheKey, cacheEntry);
          }
          return finalResults; // Return unchanged
        });

        setExecutedQuery(currentQuery);

        // Fetch field stats for non-aggregate queries
        if (!isAggregate && currentMode === 'piped') {
          const apiTime = resolveRunTimeRange(runScopeRef.current, currentTimeRange);
          // NAN-1427/1428: reduced column set (from the streamed rows mirror)
          // + request_id for cancel coverage
          const fsRequest = {
            query: currentQuery,
            start: apiTime.start,
            end: apiTime.end,
            request_id: currentRequestIdRef.current ?? undefined,
            // NAN-1559: stats must enumerate the same dataset the search
            // targeted. Read it off the REQUEST — the `dataset` state was a
            // stale closure here (not in this callback's dep list).
            dataset: request.dataset,
          };
          lastFieldStatsRequestRef.current = fsRequest;
          setFieldStatsReduced(true);
          fetchFieldStats({ ...fsRequest, columns: collectFieldStatsColumns(searchResultsRef.current, isOcsf, promotedSchemaFields), signal: runControllerRef.current?.signal })
            .then(fieldStatsResponse => {
              setServerFieldStats(fieldStatsResponse.fields ?? []);
              setFieldStatsReduced(true);
              // Persist field stats + reduced flag so a cached restore keeps
              // the explicit Show all fields behavior.
              if (cacheKey) {
                const cached = searchResultCache.get(cacheKey);
                if (cached) {
                  cached.serverFieldStats = fieldStatsResponse.fields ?? [];
                  cached.fieldStatsReduced = true;
                }
              }
            })
            .catch(err => console.warn('Failed to fetch field stats:', err));
        }

        // Capture search in notebook
        const apiTime = resolveRunTimeRange(runScopeRef.current, currentTimeRange);
        captureSearch(currentQuery, currentMode, data.total_rows_delivered, undefined, apiTime.start, apiTime.end);
      },
      onError: (data) => {
        // Flush any buffered rows before showing error
        flushRows();
        setIsStreamingResults(false);
        sseControllerRef.current = null;

        // Check if this is a network/connection error that should trigger fallback
        if (data.code === 'NETWORK_ERROR' || data.code === 'NO_BODY' || data.code === 'HTTP_ERROR' || data.code === 'RESOURCE_EXHAUSTED') {
          console.warn('SSE search is moving to durable async execution:', data.message);
          // Fall back to async polling — NAN-1602: carry the live-run intent so a
          // user search stays live even when SSE is unavailable (use_cache=false).
          api.searchAsync({ ...request, use_cache: !bypassCache }).then(asyncResponse => {
            if (asyncResponse.job_id) {
              setAsyncJobId(asyncResponse.job_id);
              queryClient.invalidateQueries({ queryKey: ['search-jobs'] });
              startAsyncJobPolling(asyncResponse.job_id, currentQuery, currentTimeRange, currentMode, isAggregate, request.dataset);
            } else {
              // Sync response
              processAsyncJobResult(asyncResponse as unknown as import('@/lib/api/types').SearchResponse, currentQuery, currentTimeRange, currentMode, isAggregate, request.dataset);
              setIsSearching(false);
              setHasSearched(true);
            }
          }).catch(fallbackErr => {
            setIsSearching(false);
            const fallbackError = handleError(fallbackErr, 'Search failed');
            setSearchError(fallbackError);
            requestQueryCorrection(fallbackError.code, fallbackError.message, currentQuery);
          });
          return;
        }

        // Application-level error from the backend
        const isParseError = /^(Parse error|Query parse error|Unexpected|Expected)/.test(data.message);
        const errCode = isParseError ? 'PARSE_ERROR' : data.code;
        setSearchError({ code: errCode, message: data.message });
        requestQueryCorrection(errCode, data.message, currentQuery);
        setIsSearching(false);
        clearAsyncJob();
        queryClient.invalidateQueries({ queryKey: ['search-jobs'] });
      },
      // NAN-1595: surface the server cache status so the "cached Ns ago · refresh"
      // banner shows even on a shared-link follow (cold client cache). The server
      // age maps to a synthetic cachedAt the existing banner already renders.
      onCacheMeta: (meta) => {
        if (meta.hit) {
          setCachedResultsTimestamp(Date.now() - (meta.ageSecs ?? 0) * 1000);
        }
      },
    }, { bypass: bypassCache });

    sseControllerRef.current = controller;
  }, [clearAsyncJob, processAsyncJobResult, startAsyncJobPolling, queryClient, fetchFieldStats, toApiTimeRange, captureSearch, requestQueryCorrection, isOcsf, promotedSchemaFields, searchSurface.browserResultCache]);

  // Main search function
  const handleSearch = useCallback(async (page: number = 1, append: boolean = false, searchQuery?: string, searchMode?: 'piped' | 'sql', searchTimeRange?: TimeRangeValue, useCache?: boolean, searchDataset?: import('@/lib/api/types').SearchDataset, requestPageSize = pageSize) => {
    // Use provided parameters or fall back to current state
    const currentQuery = searchQuery ?? query;
    const currentMode = searchMode ?? queryMode;
    const currentTimeRange = searchTimeRange ?? timeRange;
    // NAN-1825: explicit dataset override for callers that can't rely on this
    // closure's state (e.g. the history-restore effect, whose setDataset
    // hasn't re-rendered into this callback yet when the deferred call fires).
    const currentDataset = searchDataset ?? dataset;
    
    // Check for empty query
    if (!currentQuery?.trim()) {
      setSearchError({ code: 'EMPTY_QUERY', message: 'Please enter a search query' });
      return;
    }

    // NAN-173: Block SQL execution without permission
    if (currentMode === 'sql' && !canRawSql) {
      setSearchError({
        code: 'PERMISSION_DENIED',
        message: isOcsf
          ? 'Raw SQL is intentionally unavailable on the tenant-pinned OCSF lake path. Use nPL.'
          : 'Raw SQL queries require the search:sql permission. Contact your administrator.',
      });
      return;
    }
    
    // NAN-3883: one user action, one search. Production showed every run reaching
    // /api/search two or three times within the same second (three 30d scans
    // on the cell per click). A repeat of the run that just started (same
    // query, window, dataset and filter) joins it instead of aborting it and
    // starting the same scan again.
    if (!append) {
      const run = searchRunStart(currentQuery, currentMode, currentDataset, prevalenceMax, currentTimeRange, Date.now());
      if (repeatsRun(lastRunStartRef.current, run)) return;
      lastRunStartRef.current = run;
    }

    const pageContext = {
      append, offset: durableExecution && append ? asyncPageStateRef.current.results.length : (page - 1) * requestPageSize,
      page, pageSize: requestPageSize,
    };
    if (durableExecution && !reserveAsyncSearchOffset(lastAsyncOffsetRef, pageContext, asyncPageStateRef.current.complete)) return;
    if (!append) {
      artifactRef.current = null;
      clearAsyncJob();
      lastAsyncOffsetRef.current = durableExecution ? pageContext.offset : null;
      asyncPageStateRef.current = { results: [], totalCount: 0, currentPage: 1, complete: false };
      setPagingComplete(false);
    }

    if (abortControllerRef.current) abortControllerRef.current.abort();
    abortControllerRef.current = new AbortController();
    // NAN-3299: resolve the window once per run. A new run re-resolves a
    // relative pick against now; a later page reuses page 1's bounds.
    const runTimeRange = append
      ? resolveRunTimeRange(runScopeRef.current, currentTimeRange)
      : beginRunScope(currentTimeRange);
    // Generate a unique request ID for query tracking and server-side cancellation.
    // safeRandomUUID() works over plain HTTP, where crypto.randomUUID is undefined (NAN-1235).
    const requestId = safeRandomUUID();
    currentRequestIdRef.current = requestId;
    setSearchError(null);
    setQueryReviewSuggestions([]);
    setLimitWarningDismissed(false);
    setIsSearching(true);
    setPhase2(null); // NAN-1598: clear phase-2 footer status on a fresh search
    // NAN-1602: an explicit user run is live (useCache !== true → bypass); the
    // only passive caller that opts into the cache is the shared-search load.
    // Drives both the main bypass below and the special views' initial fetch.
    if (!append) setLiveRun(useCache !== true);
    // NAN-1598: also clear the (now stale) display type so a previous two-phase
    // mode's footer gate can't persist into this search. Without this, a search
    // that errors before metadata arrives (e.g. invalid nPL) would leave
    // `footerGated` true with `phase2 == null`, hanging the footer on the spinner.
    if (!durableExecution || !append) setDisplayType(undefined);
    setCachedResultsTimestamp(null); // Clear cache banner on fresh search

    // Clear AI conversation state when doing a regular search (not a refinement follow-up)
    // This keeps the state fresh when user types a new query manually
    if (!append && !searchQuery) {
      // Only clear if this is a fresh search from the user (not from AI auto-run)
      setAiConversationHistory([]);
      setRefinementQuery('');
    }

    // Show fields panel with cool animation when first search is executed
    if (!fieldsPanelVisible && !append) {
      setFieldsPanelVisible(true);
    }
    
    if (!append) {
      setSplitTiming(null);
      splitHistogramRef.current = null;
      setDurableResultCursor(null);
      setSearchResults([]);
      // NAN-2551: a real run replaces the result set, so the tail's prepended
      // rows, its held-back buffer and its watermark all belong to the old one.
      setTailState(emptyTailState<SearchResult>());
      tailSeenKeysRef.current = new Set();
      tailWatermarkRef.current = 0;
      tailHistogramCutoffRef.current = tailHistogramCutoff(0, new Date(runTimeRange.end).getTime());
      tailArrivalLogRef.current = [];
      tailReanchorRef.current.controller?.abort();
      tailReanchorRef.current = { lastRequestedMs: 0, controller: null };
      setTailChartEndMs(null);
      tailEpochRef.current += 1;
      setCompleteness(undefined);
      // The timeline belongs to the exact query + time-range snapshot. Clear
      // it with the rows so a new search cannot briefly display the previous
      // search's buckets. The SSE Metadata event installs the complete,
      // normalized replacement in one state update.
      // NAN-3273: a re-run of the same search (only the window moved) keeps
      // showing the last timeline until that replacement lands.
      const runIdentity = searchTimelineIdentity({
        query: currentQuery, mode: currentMode, dataset: currentDataset, prevalenceMax,
      });
      const onScreenIdentity = executedQueryRef.current.trim() === currentQuery.trim()
        ? timelineIdentityRef.current
        : null;
      setTimelineHold(holdTimelineForRun(
        { identity: onScreenIdentity, histogram: histogramDataRef.current },
        timelineHoldRef.current,
        runIdentity,
      ));
      timelineIdentityRef.current = runIdentity;
      setHistogramData(PENDING_TIMELINE);
      setServerFieldStats(null);
      setFieldStatsReduced(false);
      setPeakRowsScanned(0);
      setCurrentPage(1);
      // Only push to history if not restoring from back/forward navigation
      if (!isRestoringFromHistory.current) {
        updateUrl(currentQuery, currentMode, urlTimeRange(currentTimeRange, runTimeRange), undefined, true, prevalenceMax, currentDataset);
      }
      isRestoringFromHistory.current = false; // Reset the flag
      addToSearchHistory({ query: currentQuery, queryMode: currentMode, timeRange: currentTimeRange });
      refreshHistory();
    }
    
    const isAggregate = checkIfAggregateQuery(currentQuery);
    setIsAggregateQuery(isAggregate);

    // Auto-collapse fields panel for aggregate queries (fields aren't useful there)
    // but respect manual user toggle — don't fight the user
    if (!append && !userToggledFieldsPanel.current) {
      setFieldsPanelExpanded(!isAggregate);
    }
    if (!append) {
      userToggledFieldsPanel.current = false; // Reset for next search
    }

    if (!append) {
      setBaseFieldStats([]);
      setShowBaseFields(false);
    }

    try {
      const apiTimeRange = runTimeRange;
      const offset = pageContext.offset;
      let response;
      
      // Strip comments from query before sending to API
      let cleanQuery = stripComments(currentQuery);

      // Inject prevalence filter if active (piped mode only). Must go *before* any
      // pipeline commands — `stats`/`table`/`timechart`/etc. project away
      // `prevalence_min`, so appending to the end breaks with UNKNOWN_IDENTIFIER
      // in later stages. Rarity is always an event-level filter, so it belongs
      // right after the search expression.
      if (prevalenceMax < 100 && currentMode === 'piped') {
        cleanQuery = injectBeforeFirstPipe(cleanQuery, prevalenceFilterClause(prevalenceMax));
      }

      // Use SSE streaming for initial piped searches on the legacy path.
      const shouldUseStreaming = currentMode === 'piped' && !append;

      // Shared Search tries interactive admission; only server escalation uses artifacts.
      if (durableExecution) {
        const signal = abortControllerRef.current!.signal;
        const assertCurrent = () => {
          signal.throwIfAborted();
          if (currentRequestIdRef.current !== requestId) throw new DOMException('Search superseded', 'AbortError');
        };
        // NAN-3078: the job an escalated view ran as; a typed view (e.g. a
        // durable `| baseline`) renders through its product view, not as rows.
        let admittedStatus: SearchJobStatus | undefined;
        // NAN-3093: page 1's timeline is its own request, so rows are never
        // blocked on the histogram companion.
        const splitHistogram = !append && offset === 0 && !hasStatsPipeline(cleanQuery);
        splitHistogramRef.current = splitHistogram ? { requestId, rowsIn: false, startedAt: performance.now() } : null;
        if (splitHistogram) {
          api.searchHistogram({ query: cleanQuery, time_range: apiTimeRange, dataset: currentDataset }, signal)
            .then(result => {
              const split = splitHistogramRef.current;
              if (signal.aborted || !split || split.requestId !== requestId || currentRequestIdRef.current !== requestId) return;
              split.histogram = (result.histogram ?? []).map(bucket => ({ time: bucket.time, count: bucket.count }));
              split.finishedAt = performance.now();
              if (split.rowsIn) {
                split.published = true;
                setHistogramData(split.histogram);
                setSplitTiming(previous => previous ? {
                  ...previous, completionMs: Math.round(split.finishedAt! - split.startedAt),
                } : previous);
              }
              if (typeof result.total_count === 'number') {
                split.total = result.total_count;
                if (split.rowsIn) {
                  setTotalCount(result.total_count);
                  setTotalCountExact(true);
                  const state = asyncPageStateRef.current;
                  asyncPageStateRef.current = {
                    ...state,
                    totalCount: result.total_count,
                  };
                  setPagingComplete(asyncPageStateRef.current.complete);
                }
              }
            })
            .catch(err => {
              // The timeline is non-critical: rows stay, the chart stays empty.
              if (!signal.aborted) console.warn('Failed to fetch search histogram:', err);
              if (currentRequestIdRef.current === requestId) setTimelineHold(null);
            });
        }
        const admitted = await startInteractiveSearch(api, {
          query: cleanQuery, time_range: apiTimeRange, limit: requestPageSize, offset,
          use_cache: useCache, skip_field_stats: true, skip_histogram: offset > 0 || splitHistogram || hasStatsPipeline(cleanQuery),
          table_view: true, request_id: requestId, dataset: currentDataset,
        }, artifactRows(import.meta.env.VITE_SEARCH_ARTIFACT_ROWS, requestPageSize), signal,
        () => currentRequestIdRef.current === requestId, {
          isCancelled: () => signal.aborted || currentRequestIdRef.current !== requestId,
          onUnavailable: () => setSearchError({ code: AUTHORITY_UNAVAILABLE, message: AUTHORITY_NOTICE, warningSeverity: 'info' as const }),
          onRecovered: () => setSearchError(previous => previous?.code === AUTHORITY_UNAVAILABLE ? null : previous),
        }, status => {
          admittedStatus = status;
          if (status.status === 'failed' || status.status === 'cancelled') {
            // NAN-3293: a terminal job leaves the loading pane here, at the
            // status itself, not only via the poller's rejection (which a
            // superseded/aborted continuation swallows silently).
            clearAsyncJob();
            setIsSearching(false);
            if (status.status === 'failed') {
              setSearchError({ code: 'JOB_FAILED', message: status.error || 'Search job failed' });
            }
            return;
          }
          setAsyncJobId(status.job_id);
          setAsyncJobStatus(status.status);
          setAsyncJobProgress(status.progress ?? null);
          setQueuePosition(status.queue_position ?? null);
          setEstimatedWait(status.estimated_wait_seconds ?? null);
        }, meta => {
          // NAN-3809: a pasted settled search re-served from its finished
          // durable job shows "cached Nm ago · refresh"; refresh re-runs live.
          if (meta.hit && currentRequestIdRef.current === requestId) {
            setCachedResultsTimestamp(Date.now() - (meta.ageSecs ?? 0) * 1000);
          }
        });
        if (admitted.pager) {
          const pager = admitted.pager;
          const state = { pager, requestId, nextOffset: offset, busy: true };
          artifactRef.current = state;
          const rows = await pager.read(offset, requestPageSize);
          assertCurrent();
          const typedStatus = admittedStatus as SearchJobStatus | undefined;
          if (typedStatus?.status === 'completed' && processTypedDurableJobResult(typedStatus, {
            page: 0, pages: 1, total_rows: typedStatus.durable_result?.rows ?? rows.length, row_offset: 0, rows,
          }, currentQuery, currentTimeRange)) {
            state.busy = false;
            clearAsyncJob();
            asyncPageStateRef.current.complete = true;
            setPagingComplete(true);
            queryClient.invalidateQueries({ queryKey: ['search-jobs'] });
            return;
          }
          state.nextOffset = offset + rows.length;
          state.busy = false;
          clearAsyncJob();
          processAsyncJobResult({
            execution_time_ms: 0, fields: [], ...pager.response,
            results: rows, total_count: pager.totalCount,
          }, currentQuery, currentTimeRange, currentMode, isAggregate, currentDataset, 0, pageContext);
          const complete = !pager.hasMore(state.nextOffset) || rows.length < requestPageSize;
          asyncPageStateRef.current.complete = complete;
          setPagingComplete(complete);
          queryClient.invalidateQueries({ queryKey: ['search-jobs'] });
          return;
        }
        response = admitted.response;
      } else if (currentMode === 'sql') {
        response = await searchSql({ sql: cleanQuery, time_range: apiTimeRange, limit: pageSize, offset });
      } else if (shouldUseStreaming) {
        // Use SSE streaming for live result delivery
        startStreamingSearch(
          { query: cleanQuery, time_range: apiTimeRange, limit: pageSize, offset, skip_field_stats: true, skip_histogram: hasStatsPipeline(cleanQuery), table_view: true, dataset: currentDataset },
          currentQuery, currentTimeRange, currentMode, isAggregate,
          useCache !== true // NAN-1602: user runs are live (bypass); only the shared-search load (useCache=true) reads cache
        );
        // Refresh SQL panel if visible (SSE returns early, so do it before exit)
        if (showSql) {
          explainQuery({ query: cleanQuery, timeRange: apiTimeRange, dataset }).then(
            (result) => setGeneratedSql(result.sql),
            () => {} // Silently fail - SQL display is not critical
          );
        }
        return; // Exit early - results come via SSE callbacks, streaming handles cleanup
      } else {
        // table_view: slim columns (id, timestamp, message, source_type + key UDM fields)
        // Full row data fetched on demand via fetchLog when user expands a row
        // Field stats come from separate async /api/search/field-stats endpoint
        // NAN-1645: page flips (offset > 0) skip the histogram companion — the
        // timeline is page-invariant and frozen from page 1 (mirrors the
        // existing skip_field_stats behavior; the backend offset-gates too).
        response = await search({ query: cleanQuery, time_range: apiTimeRange, limit: pageSize, offset, use_cache: useCache, skip_field_stats: true, skip_histogram: offset > 0 || hasStatsPipeline(cleanQuery), table_view: true, request_id: requestId, dataset: currentDataset });
      }

      if (currentRequestIdRef.current !== requestId || abortControllerRef.current?.signal.aborted) return;

      const results: SearchResult[] = (response.results || [])
        .filter((r: unknown) => r != null && typeof r === 'object')
        .map((r: Record<string, unknown>, i: number) => ({
          id: `result-${offset + i}`,
          timestamp: eventTimestamp(r),
          source: eventSource(r),
          fields: (r && typeof r === 'object') ? r : {},
        }));
      
      if (append) {
        setSearchResults(prev => [...prev, ...results]);
      } else {
        setSearchResults(results);
        setExecutedQuery(currentQuery); // Update executed query for highlighting
      }

      // Use total_count from backend, but handle fallback for failed count queries
      // If backend returns 0 and results.length equals the limit, assume there's more data
      let effectiveTotalCount = response.total_count;
      // NAN-2550: a page-bound count is a lower bound; page flips keep the
      // page-1 fact unless this response carries a better one.
      let responseCountExact = response.total_count_exact ?? false;
      // NAN-3093: the split timeline may already have proved the exact total.
      const split = splitHistogramRef.current;
      const splitActive = !append && split !== null && split.requestId === requestId;
      if (splitActive) {
        split.rowsIn = true;
        setSplitTiming({ firstRowsMs: Math.round(performance.now() - split.startedAt) });
        if (split.total !== undefined) {
          effectiveTotalCount = split.total;
          responseCountExact = true;
        }
      }
      if (!append) {
        if (effectiveTotalCount === 0 && !responseCountExact) {
          // If we got exactly the limit, there's likely more data
          // Use a high estimate to enable pagination
          effectiveTotalCount = results.length >= requestPageSize ? results.length * 100 : results.length;
        }
        setTotalCount(effectiveTotalCount);
        // A proven companion total (including zero) stays exact; only an
        // unproven zero count needs the paging estimate above.
        setTotalCountExact(responseCountExact);
      } else if (responseCountExact || response.total_count <= offset + requestPageSize) {
        // NAN-1645: freeze the page-1 total across page flips. Page-N
        // responses carry a monotonic estimate (the count companion only runs
        // on page 1): `offset + returned + limit` on a full page (always
        // > offset + pageSize), `offset + returned` (exact) on a partial last
        // page. Adopting the mid-set estimate would replace the exact page-1
        // count, so only adopt when the server proves the end of the result
        // set — which also stops loadMore when the frozen total was itself an
        // over-estimate. Server-side (raw) page fullness is the signal here,
        // NOT results.length: post-processing (e.g. lookup + where) can shrink
        // a full raw page below pageSize while more raw pages remain.
        setTotalCount(response.total_count);
        setTotalCountExact(responseCountExact);
      }
      const pageHasMore = response.has_more ?? (
        response.total_count_exact
          ? offset + results.length < response.total_count
          : response.total_count > offset + results.length || (response.results?.length ?? 0) >= requestPageSize
      );
      setPagingComplete(!pageHasMore);
      if (durableExecution) {
        asyncPageStateRef.current = {
          results: append ? [...asyncPageStateRef.current.results, ...results] : results,
          totalCount: append && response.total_count > offset + requestPageSize
            ? asyncPageStateRef.current.totalCount : effectiveTotalCount,
          currentPage: page, complete: !pageHasMore,
        };
        setPagingComplete(asyncPageStateRef.current.complete);
      }
      setCurrentPage(page);
      if (response.generated_sql) setGeneratedSql(response.generated_sql);
      setCompleteness(response.completeness);
      const shownMs = searchDisplayTimeMs(response);
      if (shownMs !== undefined) setExecutionTimeMs(shownMs);
      // Capture display type from backend
      if (response.display_type && !append) {
        setDisplayType(response.display_type);
        // Reset table pagination when display type changes
        setTablePage(0);
      }
      // Capture column order from backend (for | table command)
      if (!append) {
        setColumnOrder(response.column_order);
      }

      // Update conversation history with result summary (for AI refinements)
      const resultCount = response.total_count || results.length;
      if (resultCount > 0 && !append) {
        setAiConversationHistory(prev => {
          if (prev.length === 0) return prev;
          const updated = [...prev];
          const lastIdx = updated.length - 1;
          // Extract some key context from results (using dynamic field access)
          const keyFields = results
            .slice(0, 3)
            .map(r => eventKeyContext(r as unknown as Record<string, unknown>, isOcsf))
            .filter(Boolean)
            .join(' | ');

          updated[lastIdx] = {
            ...updated[lastIdx],
            result_summary: `Found ${resultCount.toLocaleString()} events`,
            key_context: keyFields || undefined,
          };
          return updated;
        });
      }
      
      // Handle query warnings by converting them to errors for consistent display.
      // NAN-2550: legacy-peer compat only — a pre-NAN-2550 search service still
      // pushes the lower-bound fact as a warning, and page flips send
      // `skip_histogram` so it was never stripped server-side
      // (NAN-2512/NAN-2514). Exactness now rides on `total_count_exact`.
      const visibleWarnings = response.warnings?.filter(w => w.code !== 'LAKE_PAGE_BOUND_COUNT');
      if (visibleWarnings && visibleWarnings.length > 0) {
        // Find the most severe warning to display as the main error
        const errorWarning = visibleWarnings.find(w => w.severity === 'error');
        const warningWarning = visibleWarnings.find(w => w.severity === 'warning');
        const mainWarning = errorWarning || warningWarning || visibleWarnings[0];

        // Convert warning to error format for consistent display
        setSearchError({
          code: mainWarning.code,
          message: mainWarning.message,
          // Severity drives the drawer's icon and tint; without it an `info`
          // warning rendered with the amber AlertTriangle of a real warning.
          warningSeverity: mainWarning.severity as 'info' | 'warning' | 'error',
          // Create a minimal details object for warnings
          details: {
            position: 0,
            line: 1,
            column: 1,
            expected: [],
            suggestions: mainWarning.suggestion ? [{
              description: mainWarning.suggestion,
              replacement: '' // No replacement for warnings
            }] : [],
            formatted: mainWarning.message,
            impact: mainWarning.impact
          }
        });
      }
      
      if (response.cost_score !== undefined) {
        setQueryCostScore(response.cost_score);
      } else {
        setQueryCostScore(null);
      }
      
      // Store histogram data from API response (always update, even if empty).
      // NAN-1645: except on page flips — offset>0 requests skip the histogram
      // companion entirely, so keep the frozen page-1 timeline instead of
      // blanking it with the (absent) page-N histogram.
      const histData = response.histogram && response.histogram.length > 0
        ? response.histogram.map(bucket => ({
            time: bucket.time,
            count: bucket.count
          }))
        : [];
      if (!append && !splitActive) {
        setHistogramData(histData);
      }

      // Cache results for back-navigation (use local vars, not state which is async)
      const cacheKey = searchSurface.browserResultCache && !append ? buildCacheKey(currentQuery, currentTimeRange, currentMode, currentDataset) : null;
      if (cacheKey) {
        const cacheEntry: CachedSearchResult = {
          results,
          histogramData: histData,
          serverFieldStats: null,
          fieldStatsReduced: null,
          totalCount: effectiveTotalCount,
          totalCountExact: responseCountExact,
          executionTimeMs: searchDisplayTimeMs(response) ?? null,
          completeness: response.completeness,
          displayType: response.display_type,
          columnOrder: response.column_order,
          generatedSql: response.generated_sql || null,
          costScore: response.cost_score ?? null,
          executedQuery: currentQuery,
          isAggregateQuery: isAggregate,
          peakRowsScanned: 0,
          cachedAt: Date.now(),
        };
        searchResultCache.set(cacheKey, cacheEntry);
        // Evict expired entries if cache grows too large
        if (searchResultCache.size > 10) {
          const now = Date.now();
          for (const [k, v] of searchResultCache) {
            if (now - v.cachedAt > CACHE_TTL_MS) searchResultCache.delete(k);
          }
        }
      }

      // Fetch field stats asynchronously (separate from main search for better UX)
      // This allows search results to display immediately while field stats load in background
      if (!append && !isAggregate && currentMode === 'piped') {
        // Trigger async field stats fetch - don't await, let it run in background.
        // NAN-1427/1428: reduced column set + request_id for cancel coverage
        const fsRequest = {
          query: cleanQuery,
          start: apiTimeRange.start,
          end: apiTimeRange.end,
          request_id: requestId,
          dataset: currentDataset, // NAN-1559: stats must enumerate the same dataset the search targeted
        };
        lastFieldStatsRequestRef.current = fsRequest;
        setFieldStatsReduced(true);
        fetchFieldStats({ ...fsRequest, columns: collectFieldStatsColumns(results, isOcsf, promotedSchemaFields), signal: runControllerRef.current?.signal })
          .then(fieldStatsResponse => {
            if (durableExecution && currentRequestIdRef.current !== requestId) return;
            setServerFieldStats(fieldStatsResponse.fields ?? []);
            setFieldStatsReduced(true);
            // Update cache entry with field stats
            if (cacheKey) {
              const cached = searchResultCache.get(cacheKey);
              if (cached) {
                cached.serverFieldStats = fieldStatsResponse.fields ?? [];
                cached.fieldStatsReduced = true;
              }
            }
          })
          .catch(err => {
            // Field stats failure is non-critical, just log it
            console.warn('Failed to fetch field stats:', err);
          });
      } else if (!append) {
        // For aggregate queries or SQL mode, we compute field stats client-side
        setServerFieldStats(null);
        setFieldStatsReduced(false);
      }

      // Capture search in notebook (if active)
      if (!append) {
        const apiTime = resolveRunTimeRange(runScopeRef.current, currentTimeRange);
        captureSearch(
          currentQuery,
          currentMode,
          response.total_count || results.length,
          response.execution_time_ms,
          apiTime.start,
          apiTime.end
        );
      }

      // If SQL panel is visible, refresh the generated SQL for the new query
      if (showSql && currentMode === 'piped' && !append) {
        try {
          const result = await explainQuery({ query: cleanQuery, timeRange: apiTimeRange, dataset });
          setGeneratedSql(result.sql);
        } catch {
          // Silently fail - SQL display is not critical
        }
      }
    } catch (err) {
      if (currentRequestIdRef.current !== requestId || (err instanceof Error && err.name === 'AbortError')) return;
      if (durableExecution) {
        artifactRef.current = null;
        clearAsyncJob();
      }
      const searchErr = handleError(err, 'Unknown error');
      // NAN-3293: keep the failed job's own error (and its Retry) when the
      // poller's rejection lands after the terminal status was rendered.
      setSearchError(previous => previous?.code === 'JOB_FAILED' ? previous : searchErr);
      requestQueryCorrection(searchErr.code, searchErr.message, query);
    } finally {
      // A superseded submission can finish its backoff after a new search starts.
      if (currentRequestIdRef.current === requestId) {
        // Polling and SSE own their loading state after admission.
        if (!asyncJobPollingRef.current && !sseControllerRef.current) {
          setIsSearching(false);
        }
        setHasSearched(true);
      }
    }
  }, [query, queryMode, timeRange, pageSize, search, searchSql, updateUrl, beginRunScope, addToSearchHistory, refreshHistory, captureSearch, prevalenceMax, prevalenceFilterClause, showSql, explainQuery, startStreamingSearch, startAsyncJobPolling, queryClient, requestQueryCorrection, dataset, isOcsf, canRawSql, promotedSchemaFields, durableExecution, searchSurface.browserResultCache, clearAsyncJob, processAsyncJobResult, processTypedDurableJobResult]);

  /**
   * NAN-3254: fold one batch of tail arrivals into the histogram and slide the
   * chart window to now. Counting the rows already in hand is free; a re-fetch
   * would cost a whole-window aggregate per tick. It only touches the
   * histogram and the chart's own range, never `timeRange`, the results or
   * their scroll, so nothing re-searches.
   */
  advanceTailTimelineRef.current = (arrivalTimesMs: number[]) => {
    const nowMs = Date.now();
    const range = toApiTimeRange(timeRange);
    const spanMs = new Date(range.end).getTime() - new Date(range.start).getTime();
    const windowStartMs = Number.isFinite(spanMs) && spanMs > 0 ? nowMs - spanMs : undefined;
    const countAfterMs = tailHistogramCutoffRef.current;
    logTailArrivals(tailArrivalLogRef.current, arrivalTimesMs, countAfterMs);
    setHistogramData(current => advanceTailHistogram(current, arrivalTimesMs, { nowMs, countAfterMs, windowStartMs }));
    setTailChartEndMs(nowMs);
  };

  /**
   * NAN-3263: re-read the histogram for the rolling window `[now - span, now]`
   * and make it the live count. The tail's row feed is best-effort for events
   * the lake makes visible late, and bucket-granular roll-off saw-tooths; the
   * server read has neither problem. At most one in flight; a failure is
   * silent and the next due tick retries. The URL follows the anchored
   * window, so a reload or a copied link reproduces what is on screen.
   */
  reanchorTailTimelineRef.current = (tailIntervalMs: number) => {
    const anchor = tailReanchorRef.current;
    if (anchor.controller) return;
    const nowMs = Date.now();
    const range = toApiTimeRange(timeRange);
    const spanMs = new Date(range.end).getTime() - new Date(range.start).getTime();
    if (!tailReanchorDue(anchor.lastRequestedMs, nowMs, spanMs, tailIntervalMs)) return;
    const tailQuery = executedQuery || query;
    if (!tailQuery?.trim()) return;
    let cleanQuery = stripComments(tailQuery);
    if (prevalenceMax < 100 && queryMode === 'piped') {
      cleanQuery = injectBeforeFirstPipe(cleanQuery, prevalenceFilterClause(prevalenceMax));
    }
    const anchorEndMs = nowMs;
    const windowStart = new Date(anchorEndMs - spanMs).toISOString();
    const windowEnd = new Date(anchorEndMs).toISOString();
    const epoch = tailEpochRef.current;
    const controller = new AbortController();
    anchor.lastRequestedMs = nowMs;
    anchor.controller = controller;
    api.searchHistogram({ query: cleanQuery, time_range: { start: windowStart, end: windowEnd }, dataset }, controller.signal)
      .then(result => {
        if (controller.signal.aborted || tailEpochRef.current !== epoch) return;
        // NAN-3267: the live "N events" is this timeline's sum. An empty or
        // zero-filled read must not blank it; keep the last known timeline
        // (the tail keeps counting into it) until a read carries real data.
        if (!tailReanchorTrusted(result?.histogram, histogramDataRef.current, {
          anchorStartMs: anchorEndMs - spanMs,
          anchorEndMs,
        })) return;
        const landedMs = Date.now();
        const next = reanchorTailHistogram(result.histogram, tailArrivalLogRef.current, {
          anchorEndMs,
          nowMs: landedMs,
          windowStartMs: landedMs - spanMs,
        });
        tailArrivalLogRef.current = next.arrivalLog;
        tailHistogramCutoffRef.current = Math.max(tailHistogramCutoffRef.current, anchorEndMs);
        setHistogramData(next.histogram);
        setTailChartEndMs(landedMs);
        // The URL carries the rolling window, not the one the search started
        // on. Replace, never push: a tail must not flood browser history, and
        // the URL-sync effect must not read its own write as back-navigation.
        // NAN-3884: a relative pick already names the rolling window
        // (`time=Last 1 hour` re-resolves to now), so only a fixed range
        // needs its bounds moved.
        const params = new URLSearchParams(searchParamsRef.current);
        if (!params.get('s') && timeRange.type !== 'preset') {
          params.set('start', windowStart);
          params.set('end', windowEnd);
          params.delete('time');
          prevUrlRef.current = params.toString();
          setSearchParams(params, { replace: true });
        }
      })
      .catch(() => { /* the next due tick retries */ })
      .finally(() => {
        if (tailReanchorRef.current.controller === controller) tailReanchorRef.current.controller = null;
      });
  };

  /** Fold fresh tail rows into the list (rolling window) and the timeline. */
  const foldTailArrivals = useCallback((fresh: SearchResult[]) => {
    if (fresh.length === 0) return;
    setTailState(current => applyTailBatch(current, fresh, tailAtTopRef.current));
    advanceTailTimelineRef.current(fresh.map(row => row.timestamp?.getTime() ?? Number.NaN));
  }, []);

  /**
   * One live-tail tick (NAN-2551).
   *
   * Prepends the rows that arrived since the last tick. It deliberately does
   * NOT re-enter `handleSearch`: the tail must not touch pagination, the
   * NAN-2514 artifact, the URL, search history, the AI refinement conversation
   * or a dismissed warning. Aggregates and raw SQL have no scroll state and no
   * per-event identity to prepend against, so they keep the whole-window
   * re-run, which is the correct refresh for them.
   */
  const runTailRefresh = useCallback(async () => {
    // Re-snap the window to "now" — the tail follows the clock.
    const tailTimeRange: TimeRangeValue = timeRange.type === 'preset'
      ? { ...timeRange, refreshedAt: Date.now() }
      : (() => {
          const duration = (timeRange.end!.getTime() - timeRange.start!.getTime());
          const now = new Date();
          return { type: 'custom' as const, start: new Date(now.getTime() - duration), end: now };
        })();

    if (!tailPrependEligible(queryMode, isAggregateQuery, displayType)) {
      handleSearch(1, false, undefined, undefined, tailTimeRange);
      return;
    }

    // NAN-3244: an in-flight poll blocks the next one only while it is fresh;
    // a hung request cannot stop the tail for good.
    if (tailPollStartedAtRef.current && Date.now() - tailPollStartedAtRef.current < TAIL_STALE_GUARD_MS) return;
    const tailQuery = executedQuery || query;
    if (!tailQuery?.trim()) return;

    // NAN-2557: the tick outlives its own `await`. A fresh search started while
    // it is in flight resets the tail (`tailSeenKeysRef`, the watermark, the
    // rows) and replaces `searchResults`; without this guard the late tick
    // seeds the *new* query's seen-key set with the old query's keys and
    // prepends the old query's arrivals. Same guard every other async path on
    // this page takes.
    const epoch = tailEpochRef.current;
    const pollStartedAt = Date.now();

    tailPollStartedAtRef.current = pollStartedAt;
    try {
      const nowMs = Date.now();
      if (tailWatermarkRef.current === 0) {
        // Arm against what is on screen: its keys suppress the overlap's
        // re-delivery, its newest event time anchors the window. NAN-2557: that
        // is the tail's own rows as well as the paged set — a re-arm keeps the
        // arrivals already prepended, so it must keep their keys too.
        const base = tailArmRows(tailStateRef.current, searchResultsRef.current);
        // NAN-3244: add, never replace — the follow stream may already have
        // delivered (and keyed) rows that the trailing state ref lacks.
        // NAN-3254: bounded, keeping the newest keys.
        rememberTailKeys(tailSeenKeysRef.current, base);
        tailWatermarkRef.current = tailWatermark(
          base,
          tailWindow(nowMs, nowMs, tailInterval).startMs,
          nowMs,
        );
      }
      const askFor = tailWindow(tailWatermarkRef.current, nowMs, tailInterval);
      const cursorMs = tailWatermarkRef.current;

      let cleanQuery = stripComments(tailQuery);
      if (prevalenceMax < 100 && queryMode === 'piped') {
        cleanQuery = injectBeforeFirstPipe(cleanQuery, prevalenceFilterClause(prevalenceMax));
      }

      // NAN-3264: page down from now to the cursor (the newest event seen,
      // follow rows included), so a catch-up after the follow died or
      // stalled has no hole below a single newest page.
      const polled = await collectTailPages<Record<string, unknown>>({
        window: askFor,
        cursorMs,
        rowTimeMs: (row) => eventTimestamp(row).getTime(),
        fetchPage: async (page) => {
          if (tailEpochRef.current !== epoch) return null;
          const response = await search({
            query: cleanQuery,
            time_range: {
              start: new Date(page.startMs).toISOString(),
              end: new Date(page.endMs).toISOString(),
            },
            limit: TAIL_FETCH_LIMIT,
            offset: 0,
            skip_field_stats: true,
            // NAN-1645 precedent: the timeline belongs to the result set on screen
            // and is frozen from page 1. A tail tick is not a new result set, so
            // it neither pays for a histogram nor replaces the one being read.
            skip_histogram: true,
            table_view: true,
            dataset,
          });
          const rows = (response as { results?: unknown } | undefined)?.results;
          if (!Array.isArray(rows)) {
            // Admission escalated this page to a durable job. A tail page is
            // never worth a job — cancel it and let the next tick retry; the
            // watermark does not move, so nothing is lost by skipping.
            const jobId = (response as { job_id?: string } | undefined)?.job_id;
            if (jobId) api.cancelSearchJob(jobId).catch(() => {});
            return null;
          }
          return (rows as unknown[]).filter(
            (r): r is Record<string, unknown> => r != null && typeof r === 'object',
          );
        },
      });

      // NAN-2557: superseded while awaiting. The escalated-job cancel above
      // still runs (a leaked job is worse than a dropped tick), but nothing
      // this tick fetched belongs to the query now on screen.
      if (tailEpochRef.current !== epoch) return;

      const mapped: SearchResult[] = polled.rows.map((r, i) => ({
        // Not `result-N`: tail ids must not collide with the offset-derived
        // ids of the paged set they sit in front of.
        id: `tail-${nowMs}-${i}`,
        timestamp: eventTimestamp(r),
        source: eventSource(r),
        fields: r,
      }));
      const fresh = selectTailRows(mapped, tailSeenKeysRef.current);
      // An incomplete catch-up keeps the cursor so the next tick re-pages the
      // same span (the dedupe drops what is already shown). A page cap moves
      // it anyway: a sustained flood must not pin the window open.
      if (polled.complete || polled.capped) {
        tailWatermarkRef.current = tailWatermark(mapped, tailWatermarkRef.current, nowMs);
      }
      foldTailArrivals(fresh);
    } catch {
      // A failed tick is self-healing: the next one re-asks an overlapping
      // window, so a transient failure cannot lose rows. Never surface it as a
      // search error — that would auto-stop the tail.
    } finally {
      if (tailPollStartedAtRef.current === pollStartedAt) tailPollStartedAtRef.current = 0;
    }
  }, [timeRange, queryMode, isAggregateQuery, displayType, handleSearch, executedQuery, query,
      tailInterval, prevalenceMax, prevalenceFilterClause, search, dataset, foldTailArrivals]);

  useEffect(() => { runTailRefreshRef.current = () => { void runTailRefresh(); }; }, [runTailRefresh]);

  scheduleTailRetryRef.current = (nowMs: number) => {
    const sup = tailSupervisorRef.current;
    if (sup.status !== 'down' || sup.reconnectAtMs <= nowMs) return;
    if (tailRetryTimerRef.current) clearTimeout(tailRetryTimerRef.current);
    tailRetryTimerRef.current = setTimeout(() => {
      tailRetryTimerRef.current = null;
      tailTickRef.current();
    }, sup.reconnectAtMs - nowMs);
  };

  startTailFollowRef.current = () => {
    const tailQuery = executedQuery || query;
    if (!tailQuery.trim()) return;
    const nowMs = Date.now();
    tailSupervisorRef.current = tailFollowConnecting(tailSupervisorRef.current, nowMs);
    const generation = tailSupervisorRef.current.generation;
    // NAN-3244: add, never replace. `tailStateRef` trails the last render, so
    // a reconnect right after a prepend would otherwise forget those keys
    // and let the next batch deliver the same events twice.
    rememberTailKeys(tailSeenKeysRef.current, tailArmRows(tailStateRef.current, searchResultsRef.current));
    const followRange: TimeRangeValue = timeRange.type === 'preset'
      ? { ...timeRange, refreshedAt: nowMs }
      : (() => {
          const duration = timeRange.end!.getTime() - timeRange.start!.getTime();
          return { type: 'custom' as const, start: new Date(nowMs - duration), end: new Date(nowMs) };
        })();
    const apiRange = toApiTimeRange(followRange);
    let cleanQuery = stripComments(tailQuery);
    if (prevalenceMax < 100) {
      cleanQuery = injectBeforeFirstPipe(cleanQuery, prevalenceFilterClause(prevalenceMax));
    }
    const epoch = tailEpochRef.current;
    // NAN-3244: every end of this connection — completed, error event, HTTP
    // error, network drop, or a bare close — marks the follow down and runs a
    // tick now, which polls immediately and reconnects after backoff. Only an
    // abort (the tail was stopped or re-armed) is silent.
    const ended = (outcome: 'completed' | 'error' | 'unsupported') => {
      if (controller.signal.aborted) return;
      const nowMs = Date.now();
      tailSupervisorRef.current = tailFollowEnded(tailSupervisorRef.current, generation, outcome, nowMs);
      tailTickRef.current();
      scheduleTailRetryRef.current(nowMs);
    };
    const opened = () => {
      if (controller.signal.aborted) return;
      const nowMs = Date.now();
      tailSupervisorRef.current = tailFollowActivity(
        tailFollowOpened(tailSupervisorRef.current, generation, nowMs),
        generation,
        nowMs,
      );
    };
    const controller = api.searchStreamSSE({
      query: cleanQuery,
      time_range: { start: apiRange.start, end: new Date(nowMs).toISOString() },
      limit: TAIL_FETCH_LIMIT,
      offset: 0,
      skip_field_stats: true,
      skip_histogram: true,
      table_view: false,
      dataset,
      request_id: safeRandomUUID(),
    }, {
      onStarted: opened,
      // NAN-3264: proof of life from the follow loop itself (stall detection).
      onHeartbeat: opened,
      onRows: (data) => {
        opened();
        if (tailEpochRef.current !== epoch || controller.signal.aborted) return;
        const mapped: SearchResult[] = (data.rows || [])
          .filter((row): row is Record<string, unknown> => row != null && typeof row === 'object')
          .map((row, i) => ({
            id: `tail-follow-${nowMs}-${data.batch_index}-${i}`,
            timestamp: eventTimestamp(row),
            source: eventSource(row),
            fields: row,
            fullEvent: true,
          }));
        foldTailArrivals(selectTailRows(mapped, tailSeenKeysRef.current));
        // NAN-3264: follow rows advance the poll cursor, so a poll after the
        // follow ends resumes from the last event it delivered.
        tailWatermarkRef.current = tailWatermark(mapped, tailWatermarkRef.current, Date.now());
      },
      onCompleted: () => ended('completed'),
      onError: (error) => ended(tailFollowOutcome(error?.code)),
    }, { follow: true });
    tailFollowControllerRef.current = controller;
  };

  /** Show the arrivals held back while the analyst was reading further down. */
  const showBufferedTailRows = useCallback(() => {
    setTailState(current => flushTailBuffer(current));
    resultsScrollContainer?.current?.scrollTo({ top: 0, behavior: 'smooth' });
  }, [resultsScrollContainer]);

  /**
   * What the results list renders: live-tail arrivals in front of the paged
   * result set. `searchResults` itself is never rewritten by the tail, so every
   * offset, page sum and artifact read below is unchanged (NAN-2512/NAN-2514).
   */
  const displayResults = useMemo(
    () => (tailState.rows.length > 0 ? [...tailState.rows, ...searchResults] : searchResults),
    [tailState.rows, searchResults],
  );

  const handleStopSearch = useCallback(() => {
    artifactRef.current = null;
    // Abort SSE stream (closes connection, backend detects disconnect and kills ClickHouse query)
    if (sseControllerRef.current) {
      sseControllerRef.current.abort();
      sseControllerRef.current = null;
      setIsStreamingResults(false);
    }
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      abortControllerRef.current = null;
    }
    runControllerRef.current?.abort();
    setIsSearching(false);
    setTailActive(false);
    // Cancel the query on the server side (fire-and-forget)
    if (currentRequestIdRef.current) {
      api.cancelSearch(currentRequestIdRef.current).catch(() => {});
      currentRequestIdRef.current = null;
    }
    // Also cancel any async job (fallback path)
    if (asyncJobId) {
      api.cancelSearchJob(asyncJobId).catch(() => {});
      clearAsyncJob();
    }
  }, [asyncJobId, clearAsyncJob]);

  const loadArtifactRows = useCallback(async (offset: number, count: number, tableTarget?: number) => {
    const state = artifactRef.current;
    if (!state || state.busy) return;
    state.busy = true;
    setIsSearching(true);
    try {
      const rows = await state.pager.read(offset, count);
      if (artifactRef.current !== state || currentRequestIdRef.current !== state.requestId) return;
      const results: SearchResult[] = rows.map((fields, index) => ({
        id: `result-${offset + index}`, timestamp: eventTimestamp(fields), source: eventSource(fields), fields,
      }));
      const context = { append: true, offset, page: Math.floor(offset / pageSize) + 1, pageSize: count };
      const merged = mergeAsyncSearchPage(asyncPageStateRef.current, results, state.pager.totalCount, context);
      // Exact initial counts stay fixed. Older durable services expose only a
      // lower bound; grow that bound as each artifact arrives.
      merged.totalCount = state.pager.totalCount;
      merged.complete ||= !state.pager.hasMore(offset + rows.length);
      asyncPageStateRef.current = merged;
      state.nextOffset = offset + rows.length;
      setSearchResults(merged.results);
      setTotalCount(merged.totalCount);
      setPagingComplete(merged.complete);
      setCurrentPage(merged.currentPage);
      if (tableTarget !== undefined) setTablePage(tableTarget);
    } catch (error) {
      if (artifactRef.current === state && currentRequestIdRef.current === state.requestId) {
        setSearchError(handleError(error, 'Failed to read search artifact'));
      }
    } finally {
      state.busy = false;
      if (artifactRef.current === state && currentRequestIdRef.current === state.requestId) setIsSearching(false);
    }
  }, [pageSize]);

  const prefetchArtifact = useCallback((visibleEnd: number) => {
    const state = artifactRef.current;
    if (!state || state.busy || asyncPageStateRef.current.complete) return;
    void state.pager.prefetch(visibleEnd, state.nextOffset).catch(error => {
      // A failed speculative request is retried by the next foreground read.
      if (artifactRef.current === state && currentRequestIdRef.current === state.requestId) {
        console.warn('Search artifact prefetch failed:', error);
      }
    });
  }, []);

  /**
   * Scroll telemetry from the virtualised list. NAN-2551: live-tail arrivals
   * sit in front of the paged set, so the visible range is translated back
   * into paged-row space before the artifact prefetch threshold sees it, and
   * the range start decides whether arrivals prepend or are held back.
   */
  const handleVisibleRowsChange = useCallback((visibleEnd: number, visibleStart?: number) => {
    tailAtTopRef.current = (visibleStart ?? 0) <= 0;
    prefetchArtifact(Math.max(0, visibleEnd - tailStateRef.current.rows.length));
  }, [prefetchArtifact]);

  const loadMore = useCallback(async () => {
    if (pagingComplete) return;
    if (artifactRef.current) {
      await loadArtifactRows(artifactRef.current.nextOffset, pageSize);
      return;
    }
    if (durableResultCursor) {
      const nextPage = durableResultCursor.loadedPage + 1;
      if (isSearching || nextPage >= durableResultCursor.pages) return;
      setIsSearching(true);
      try {
        const page = await api.getSearchJobResultPage(durableResultCursor.jobId, nextPage);
        const results: SearchResult[] = page.rows
          .filter((r: unknown) => r != null && typeof r === 'object')
          .map((r: Record<string, unknown>, i: number) => ({
            id: `result-${page.row_offset + i}`,
            timestamp: eventTimestamp(r),
            source: eventSource(r),
            fields: r,
          }));
        setSearchResults((current) => [...current, ...results]);
        setDurableResultCursor((current) => current ? {
          ...current,
          loadedPage: page.page,
          rowOffset: 0,
        } : current);
      } catch (err) {
        console.error('Failed to fetch durable result page:', err);
      } finally {
        setIsSearching(false);
      }
      return;
    }
    // Page exhaustion is independent of the display count.
    if (!isSearching) {
      handleSearch(currentPage + 1, true);
    }
  }, [pagingComplete, durableResultCursor, isSearching, searchResults.length, totalCount, totalCountExact, currentPage, handleSearch, loadArtifactRows, pageSize]);

  // Handler for table pagination - fetches page from server
  const handleTablePageChange = useCallback(async (newPage: number, overrideSize?: number) => {
    const effectiveSize = overrideSize ?? tablePageSize;
    const artifact = artifactRef.current;
    if (artifact) {
      const end = (newPage + 1) * effectiveSize;
      if (end <= searchResults.length || !artifact.pager.hasMore(artifact.nextOffset)) {
        setTablePage(newPage);
        prefetchArtifact(end);
      } else {
        await loadArtifactRows(artifact.nextOffset, end - searchResults.length, newPage);
        prefetchArtifact(end);
      }
      return;
    }
    if (durableExecution && !durableResultCursor) {
      if (isSearching || !executedQuery) return;
      const end = (newPage + 1) * effectiveSize;
      if (end > searchResults.length && !pagingComplete) {
        const pending = handleSearch(currentPage + 1, true, executedQuery, undefined, undefined, undefined, undefined, end - searchResults.length);
        const requestId = currentRequestIdRef.current;
        await pending;
        if (currentRequestIdRef.current !== requestId) return;
      }
      if (asyncPageStateRef.current.results.length >= end || asyncPageStateRef.current.complete) setTablePage(newPage);
      return;
    }
    if (durableResultCursor) {
      const absoluteOffset = newPage * effectiveSize;
      const targetPage = durableArtifactPageForOffset(
        absoluteOffset,
        durableResultCursor.pageRows,
        durableResultCursor.pages,
      );
      if (targetPage === durableResultCursor.loadedPage || durableResultCursor.pages === 0) {
        setTablePage(newPage);
        return;
      }

      setIsSearching(true);
      try {
        const page = await api.getSearchJobResultPage(durableResultCursor.jobId, targetPage);
        const results: SearchResult[] = page.rows
          .filter((r: unknown) => r != null && typeof r === 'object')
          .map((r: Record<string, unknown>, i: number) => ({
            id: `result-${page.row_offset + i}`,
            timestamp: eventTimestamp(r),
            source: eventSource(r),
            fields: r,
          }));
        setSearchResults(results);
        setDurableResultCursor((current) => current ? {
          ...current,
          loadedPage: page.page,
          rowOffset: page.row_offset,
        } : current);
        setTablePage(newPage);
      } catch (err) {
        console.error('Failed to fetch durable result page:', err);
      } finally {
        setIsSearching(false);
      }
      return;
    }
    // Use displayType to determine if we need server-side pagination
    // displayType === 'table' includes stats, table command, etc.
    const needsServerPagination = displayType === 'table' || displayType === 'transaction' || isAggregateQuery;

    // For non-table queries, just update local state (client-side pagination)
    if (!needsServerPagination || !executedQuery) {
      setTablePage(newPage);
      return;
    }

    // If all data is already loaded (e.g. aggregation queries stream all groups),
    // paginate client-side — PaginatedTable slices to the current page. Skip this
    // fast-path when the caller changed the page size, since we now need to refetch
    // to honour the new limit.
    if (overrideSize === undefined && totalCountExact && searchResults.length >= totalCount) {
      setTablePage(newPage);
      return;
    }

    // For table/aggregate queries where we need more data, fetch from server
    if (abortControllerRef.current) abortControllerRef.current.abort();
    abortControllerRef.current = new AbortController();
    setIsSearching(true);

    try {
      const apiTimeRange = resolveRunTimeRange(runScopeRef.current, timeRange);
      const offset = newPage * effectiveSize;
      let cleanQuery = stripComments(executedQuery);

      // Inject prevalence filter before any pipeline commands (see initial search
      // path above — rarity is an event-level filter and breaks in stage_2 scope
      // if appended after `stats`/`table`/`timechart`/etc).
      if (prevalenceMax < 100 && queryMode === 'piped') {
        cleanQuery = injectBeforeFirstPipe(cleanQuery, prevalenceFilterClause(prevalenceMax));
      }

      const response = queryMode === 'sql'
        ? await searchSql({ sql: cleanQuery, time_range: apiTimeRange, limit: effectiveSize, offset })
        : await search({ query: cleanQuery, time_range: apiTimeRange, limit: effectiveSize, offset, skip_field_stats: true, skip_histogram: offset > 0 || hasStatsPipeline(cleanQuery), dataset });

      if (abortControllerRef.current?.signal.aborted) return;

      const results: SearchResult[] = (response.results || [])
        .filter((r: unknown) => r != null && typeof r === 'object')
        .map((r: Record<string, unknown>, i: number) => ({
          id: `result-${offset + i}`,
          timestamp: eventTimestamp(r),
          source: eventSource(r),
          fields: (r && typeof r === 'object') ? r : {},
        }));

      setSearchResults(results);
      setTablePage(newPage);
      // Total count should remain the same from initial query
    } catch (err) {
      if ((err as Error)?.name === 'AbortError') return;
      console.error('Failed to fetch aggregate page:', err);
    } finally {
      setIsSearching(false);
    }
  }, [durableExecution, isSearching, pagingComplete, currentPage, handleSearch, durableResultCursor, isAggregateQuery, displayType, executedQuery, searchResults.length, timeRange, tablePageSize, totalCount, totalCountExact, queryMode, prevalenceMax, prevalenceFilterClause, search, searchSql, dataset, loadArtifactRows, prefetchArtifact]);

  const handleTablePageSizeChange = useCallback((newSize: number) => {
    setTablePageSize(newSize);
    // Reset to first page and refetch with the new size — pass override so the
    // fetch doesn't use the stale state value still in handleTablePageChange's closure.
    handleTablePageChange(0, newSize);
  }, [handleTablePageChange]);

  // Fetch full log data on row expand (table_view mode)
  // Uses narrow time window around event timestamp for efficient partition pruning.
  // NAN-1032: sourceType lets ClickHouse use the (source_type, timestamp, ...) PK
  // for a tight range read — without it, S3-backed historical lookups take 12–60s.
  const fetchLog = useCallback(async (logId: string, eventTimestamp: Date, sourceType?: string): Promise<Record<string, unknown> | null> => {
    try {
      // Create a 2-second window around the event timestamp for efficient lookup
      // This narrows the query to a single partition instead of the full search range
      const start = new Date(eventTimestamp.getTime() - 1000);
      const end = new Date(eventTimestamp.getTime() + 1000);
      const narrowTimeRange = { start: start.toISOString(), end: end.toISOString() };
      const response = await api.fetchLog(logId, narrowTimeRange, sourceType);
      if (response.event) return response.event;
      // Narrow time window missed — retry without time range constraint
      const fallback = await api.fetchLog(logId, undefined, sourceType);
      return fallback.event;
    } catch (error) {
      console.error('Failed to fetch log:', error);
      return null;
    }
  }, []);

  // Load shared search from short ID
  const loadSharedSearch = useCallback(async (shortId: string) => {
    try {
      const shared = await getSharedSearch(shortId);
      setQuery(shared.query);
      setQueryMode(shared.query_mode as 'piped' | 'sql');
      if (shared.time_range_type === 'custom' && shared.time_range_start && shared.time_range_end) {
        setTimeRange({ type: 'custom', start: new Date(shared.time_range_start), end: new Date(shared.time_range_end) });
      } else if (shared.time_range_preset) {
        setTimeRange({ type: 'preset', preset: shared.time_range_preset });
      }
      setShortUrlId(shortId);
      // Show fields panel since we're loading a search
      setFieldsPanelVisible(true);
      // Use cache for shared searches (fixed time range, multiple viewers)
      const loadedTimeRange: TimeRangeValue = shared.time_range_type === 'custom' && shared.time_range_start && shared.time_range_end
        ? { type: 'custom', start: new Date(shared.time_range_start), end: new Date(shared.time_range_end) }
        : shared.time_range_preset
          ? { type: 'preset', preset: shared.time_range_preset }
          : { type: 'preset', preset: 'Last hour' };
      setTimeout(() => handleSearch(1, false, shared.query, shared.query_mode as 'piped' | 'sql', loadedTimeRange, true), 100);
    } catch (err) {
      setSearchError(handleError(err, 'Failed to load shared search'));
    }
  }, [getSharedSearch, handleSearch]);

  // AI Query Builder - uses natural language input to generate piped query
  // isRefinement: true when this is a follow-up query in a conversation
  const handleAskMelod = useCallback(async (overrideQuery?: string, isRefinement = false) => {
    // POST /api/melod/query + GET /api/melod/jobs/{id} — served on every
    // profile; `capabilities.melod` already reflects the platform provider.
    if (!capabilities.melod) return;
    const queryToUse = overrideQuery ?? naturalLanguageQuery;
    if (!queryToUse?.trim()) return;
    setAiError(null);
    setAiResponse(null);
    setAiGeneratedSql(null);
    setAiFieldsUsed([]);
    setAiComplexity(null);
    setAiSuggestedTimeRange(null);
    setAiReasoningSteps([]);
    setShowAiThinking(false);
    setShowAiDetails(false);
    setShowAiSuggestion(false); // Hide the suggestion pill
    setRefinementQuery('');

    // Clear conversation history if this is a fresh query (not a refinement)
    if (!isRefinement) {
      setAiConversationHistory([]);
    }

    try {
      const apiTimeRange = toApiTimeRange(timeRange);
      const result = await buildQueryJob.start(() => api.melodBuildQuery({
        message: queryToUse,
        time_range: apiTimeRange,
        query_mode: userQueryMode,
        session_id: aiSessionId,
        // Pass conversation history for refinements
        conversation_history: isRefinement ? aiConversationHistory : undefined,
      }));
      if (result.session_id) {
        setAiSessionId(result.session_id);
        sessionStorage.setItem('melod-session-search', result.session_id);
      }
      if (result.query) {
        // Mark that AI is setting the query (so onQueryChange doesn't clear AI state)
        isAiSettingQueryRef.current = true;

        // Handle both Standard (PPL) and Advanced (SQL) modes
        if (userQueryMode === 'advanced' && result.query.sql_query) {
          // Advanced mode: use raw SQL query
          setQuery(result.query.sql_query);
          setQueryMode('sql');
        } else if (result.query.npl_query) {
          // Standard mode: use PPL query
          setQuery(result.query.npl_query);
          setQueryMode('piped');
        }

        // Reset the flag after a short delay to allow the state update to process
        setTimeout(() => { isAiSettingQueryRef.current = false; }, 50);

        setAiResponse(result.query.explanation || result.message);
        setShowAiThinking(true); // Auto-expand panel so users see reasoning & refinement option

        // Capture additional AI response data for the thinking panel
        if (result.query.sql_query) {
          setAiGeneratedSql(result.query.sql_query);
        }
        if (result.query.fields_used && result.query.fields_used.length > 0) {
          setAiFieldsUsed(result.query.fields_used);
        }
        if (result.query.estimated_complexity) {
          setAiComplexity(result.query.estimated_complexity);
        }
        if (result.query.reasoning_steps && result.query.reasoning_steps.length > 0) {
          setAiReasoningSteps(result.query.reasoning_steps);
        }
        
        // Apply suggested time range if provided, and compute effective range for auto-search
        let effectiveTimeRange = timeRange;
        if (result.query.suggested_time_range) {
          const suggested = result.query.suggested_time_range;
          setAiSuggestedTimeRange(suggested.description);
          if (suggested.preset) {
            // Map preset names to display names
            const presetMap: Record<string, string> = {
              'last_15_minutes': 'Last 15 minutes',
              'last_30_minutes': 'Last 30 minutes',
              'last_1_hour': 'Last 1 hour',
              'last_2_hours': 'Last 2 hours',
              'last_4_hours': 'Last 4 hours',
              'last_6_hours': 'Last 6 hours',
              'last_12_hours': 'Last 12 hours',
              'last_24_hours': 'Last 24 hours',
              'last_7_days': 'Last 7 days',
              'last_30_days': 'Last 30 days',
              'last_90_days': 'Last 90 days',
              'today': 'Today',
              'yesterday': 'Yesterday',
            };
            const displayPreset = presetMap[suggested.preset] || suggested.description;
            effectiveTimeRange = { type: 'preset', preset: displayPreset };
            setTimeRange(effectiveTimeRange);
          } else if (suggested.duration_seconds) {
            // Create custom time range from duration
            const end = new Date();
            const start = new Date(end.getTime() - suggested.duration_seconds * 1000);
            effectiveTimeRange = { type: 'custom', start, end };
            setTimeRange(effectiveTimeRange);
          }
        }

        // Check if query validation passed (no warning status in validation step)
        const validationStep = result.query.reasoning_steps?.find(
          step => step.step_type === 'validation'
        );
        const hasValidationWarning = validationStep?.details &&
          (validationStep.details as Record<string, unknown>).status === 'warning';

        // Collapse AI thinking panel after query generation (user can expand to see details)
        setShowAiThinking(false);

        // Auto-run search after generating query (unless there's a validation warning)
        // Use the appropriate query and mode based on user preference
        const isAdvancedMode = userQueryMode === 'advanced';
        const generatedQuery = isAdvancedMode ? result.query.sql_query : result.query.npl_query;
        const searchMode = isAdvancedMode ? 'sql' : 'piped';

        if (!hasValidationWarning && generatedQuery) {
          // Store the explanation in the cache for URL sharing when the
          // profile serves the cache (see SearchSurface.explanationCache).
          if (searchSurface.explanationCache) {
            try {
              await storeQueryExplanation({
                query: generatedQuery,
                query_mode: searchMode,
                natural_language_prompt: naturalLanguageQuery,
                explanation: result.query.explanation,
                reasoning_steps: result.query.reasoning_steps?.map(step => ({
                  step_type: step.step_type,
                  title: step.title,
                  description: step.description,
                  details: step.details as Record<string, unknown> | undefined,
                })),
                fields_used: result.query.fields_used,
                generated_sql: result.query.sql_query,
                complexity: result.query.estimated_complexity,
                suggested_time_range: result.query.suggested_time_range?.description,
              });
            } catch {
              // Silently fail - caching is optional
              console.warn('Failed to cache query explanation');
            }
          }

          // Add to conversation history for potential refinements
          setAiConversationHistory(prev => [...prev, {
            user_message: queryToUse,
            generated_query: generatedQuery,
            // Result summary will be updated after search completes
          }]);

          // Auto-search with the effective time range (not stale closure value)
          setTimeout(() => {
            handleSearch(1, false, generatedQuery, searchMode, effectiveTimeRange);
          }, 100);
        }
      } else {
        // No query generated - show the message (could be an error like "source not found")
        setAiError(result.message);
      }
    } catch (err) {
      setAiError(err instanceof Error ? err.message : 'Failed to generate query');
    }
  }, [capabilities.melod, searchSurface.explanationCache, naturalLanguageQuery, timeRange, buildQueryJob, handleSearch, storeQueryExplanation, userQueryMode, aiConversationHistory]);

  // SQL explanation
  const handleShowSql = useCallback(async () => {
    if (showSql) { setShowSql(false); return; }
    try {
      const apiTimeRange = toApiTimeRange(timeRange);
      // Strip comments from query before sending to API
      const cleanQuery = stripComments(query);
      const result = await explainQuery({ query: cleanQuery, timeRange: apiTimeRange });
      setGeneratedSql(result.sql);
      setShowSql(true);
    } catch (err) {
      setSearchError(handleError(err, 'Failed to generate SQL'));
    }
  }, [showSql, query, timeRange, explainQuery]);

  // Save search
  const handleSaveSearch = useCallback(async () => {
    if (!saveSearchName.trim()) return;
    try {
      await createSavedSearch({
        name: saveSearchName,
        query,
        query_mode: queryMode,
        time_range: toApiTimeRange(timeRange),
        visibility: saveSearchShared ? 'public' : 'private',
      });
      setSaveDialogOpen(false);
      setSaveSearchName('');
      setSaveSearchDescription('');
      setSaveSearchShared(false);
      refetchSaved();
    } catch (err) {
      setSearchError(handleError(err, 'Failed to save search'));
    }
  }, [saveSearchName, saveSearchShared, query, queryMode, timeRange, createSavedSearch, refetchSaved]);

  // NAN-2209: one-click group-by from the field index. Keeps the analyst's
  // base filters, drops whatever pipeline followed them, and runs immediately —
  // the same shape FieldValueMenu emits, so both entry points stay consistent.
  const groupByField = useCallback((field: string) => {
    const newQuery = buildGroupByQuery(query, field);
    setQuery(newQuery);
    handleSearch(1, false, newQuery, queryMode, timeRange);
  }, [query, queryMode, timeRange, handleSearch]);

  // Add filter to query
  const addToQuery = useCallback((field: string, value: string, exclude: boolean = false) => {
    // Check if this is an enriched field (starts with _)
    // These fields are computed at query time and must be filtered with | where
    const isEnrichedField = field.startsWith('_');

    // Detect if value is numeric (don't quote numbers in where clause)
    const isNumeric = !isNaN(Number(value)) && value.trim() !== '';

    let newQuery: string;

    if (isEnrichedField) {
      // For enriched fields, append a | where clause at the end
      const op = exclude ? '!=' : '=';
      const formattedValue = isNumeric ? value : `"${nplQuotedBody(value)}"`;
      const whereClause = `| where ${field} ${op} ${formattedValue}`;
      newQuery = query ? `${query} ${whereClause}` : `* ${whereClause}`;
    } else {
      // For regular fields, add to the search clause BEFORE pipe commands
      const op = exclude ? '!=' : '=';
      // NAN-2184: double backslashes and strip `"` — nPL has no `\"` escape.
      const escapedValue = nplQuotedBody(value);
      const newFilter = `${field}${op}"${escapedValue}"`;

      if (!query) {
        newQuery = newFilter;
      } else {
        // Split query into base search and pipe commands
        const baseSearch = getBaseSearch(query);
        const pipeCommands = getPipeCommands(query);

        // Add filter to base search, then re-append pipe commands
        const newBaseSearch = baseSearch ? `${baseSearch} ${newFilter}` : newFilter;
        newQuery = pipeCommands ? `${newBaseSearch} ${pipeCommands}` : newBaseSearch;
      }
    }

    setQuery(newQuery);
    // Pass newQuery directly to handleSearch since setState is async
    handleSearch(1, false, newQuery, queryMode, timeRange);
  }, [query, queryMode, timeRange, handleSearch]);

  // Drilldown from stats results - builds a new query from the grouping field values
  const handleDrilldown = useCallback((filters: Record<string, unknown>) => {
    // Get the base search (everything before the first pipe)
    const baseSearch = getBaseSearch(query);

    // Fields to exclude from drilldown filters
    // - timestamp: already constrained by time range picker, exact string match is fragile
    // - bytes_out/bytes_in: numeric fields that shouldn't be exact-matched
    // - _identityClause / _tableCommand / _timeRangeOverride: handled separately
    const excludeFromDrilldown = new Set([
      'timestamp', 'bytes_out', 'bytes_in', 'bytes', 'duration', 'response_time',
      '_identityClause', '_tableCommand', '_timeRangeOverride', '_rawClause',
    ]);

    // Check for identity clause (pre-built OR expression from asset view)
    const identityClause = filters._identityClause as string | undefined;
    // Pre-built raw search clause AND-ed onto the base search (e.g. the prevalence
    // scatter's `(file_hash="…" OR process_hash="…")` artifact drill). Kept out of
    // the field=value builder since it's an OR expression across two fields.
    const rawClause = filters._rawClause as string | undefined;
    // Check for table command (pre-built | table from asset view drilldown)
    const tableCommand = filters._tableCommand as string | undefined;
    // Check for time-range override (per-bucket timeline drill — NAN-1050)
    const timeRangeOverride = filters._timeRangeOverride as
      | { start: string; end: string }
      | undefined;
    const overrideTimeRange: TimeRangeValue | null = timeRangeOverride
      ? {
          type: 'custom',
          start: new Date(timeRangeOverride.start),
          end: new Date(timeRangeOverride.end),
        }
      : null;

    // Build filter clauses from the row's grouping fields
    const filterClauses = Object.entries(filters)
      .filter(([field, value]) => value !== null && value !== undefined && !excludeFromDrilldown.has(field))
      .map(([field, value]) => {
        const strValue = typeof value === 'string' ? value : String(value);
        // NAN-2184: double backslashes and strip `"` — nPL has no `\"` escape.
        const escapedValue = nplQuotedBody(strValue);
        return `${field}="${escapedValue}"`;
      });

    // Add identity clause if present (from asset view drilldown)
    if (identityClause) {
      filterClauses.unshift(identityClause);
    }

    // Combine base search with filters
    // If identity clause is present, skip base search - the identity clause already provides asset context
    let newQuery: string;
    if (identityClause) {
      // Identity clause replaces the base search for asset view drilldowns
      newQuery = filterClauses.join(' ');
    } else {
      newQuery = baseSearch.trim();
      // NAN-1457: don't re-append a filter the base search already carries. The
      // asset view's base is `<field>="<value>"` (the `| asset` source) and the
      // Investigate pivot passes that same `{field: value}`, which produced
      // `user="mmoore" user="mmoore"`. Match on a word boundary so `dest_user=…`
      // doesn't shadow `user=…`.
      const escapeRegExp = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const baseHasClause = (clause: string) =>
        new RegExp(`(^|[\\s(])${escapeRegExp(clause)}($|[\\s)])`).test(newQuery);
      const newClauses = filterClauses.filter((c) => !baseHasClause(c));
      if (newClauses.length > 0) {
        newQuery = newQuery ? `${newQuery} ${newClauses.join(' ')}` : newClauses.join(' ');
      }
    }
    
    // AND a pre-built raw clause (artifact scatter drill) onto the search. Wrap
    // the existing search in parens so top-level ORs (`a OR b OR c`) don't let the
    // AND bind only to the last term — otherwise the drill returns the same set.
    if (rawClause) {
      const base = newQuery.trim();
      newQuery = base ? `(${base}) AND ${rawClause}` : rawClause;
    }

    // Append table command if present (from asset view "Search as table")
    if (tableCommand) {
      newQuery = `${newQuery} ${tableCommand}`;
    }

    // Update query and force re-search
    setQuery(newQuery);
    setQueryMode('piped');
    // Narrow the time picker to the bucket window when drilling from the
    // timeline (NAN-1050). The user sees their narrowed range and can widen
    // back out from the time picker.
    if (overrideTimeRange) {
      setTimeRange(overrideTimeRange);
    }
    const isAggregate = checkIfAggregateQuery(newQuery);
    setIsAggregateQuery(isAggregate);
    if (!isAggregate) {
      setDisplayType(undefined); // Reset display type only for raw queries
    }
    setColumnOrder(undefined); // Reset column order from previous query
    setTablePage(0); // Reset pagination
    setSearchResults([]); // Clear current results
    setCompleteness(undefined);
    setServerFieldStats(null); // Clear server field stats
    setFieldStatsReduced(false);

    // Use a ref to track the new query and trigger search
    setTimeout(() => {
      // Manually trigger search with the new query
      const runDrilldownSearch = async () => {
        setSearchError(null);
        setIsSearching(true);
        // Don't clear histogram here - keep showing previous data while loading
        setCurrentPage(1);

        // Effective range for this drilldown — the override wins over the
        // (just-updated) state because React state updates are async and we
        // need the bucket window in this synchronous closure.
        const effectiveTimeRange = overrideTimeRange ?? timeRange;

        // NAN-3299: resolve the window once; the URL carries the same bounds.
        const drilldownTimeRange = beginRunScope(effectiveTimeRange);

        // Update URL and add to search history
        updateUrl(newQuery, 'piped', urlTimeRange(effectiveTimeRange, drilldownTimeRange), undefined, true, undefined, dataset);
        addToSearchHistory({ query: newQuery, queryMode: 'piped', timeRange: effectiveTimeRange });
        refreshHistory();

        try {
          const apiTimeRange = drilldownTimeRange;
          // Strip comments from query before sending to API
          const cleanQuery = stripComments(newQuery);
          // NAN-1825: drilldowns must stay on the dataset the source search ran
          // against — dropping it silently re-queried logs for spans/metrics/risk.
          const response = await search({ query: cleanQuery, time_range: apiTimeRange, limit: pageSize, offset: 0, dataset });
          
          const results: SearchResult[] = (response.results || [])
            .filter((r: unknown) => r != null && typeof r === 'object')
            .map((r: Record<string, unknown>, i: number) => ({
              id: `result-${i}`,
              timestamp: eventTimestamp(r),
              source: eventSource(r),
              fields: (r && typeof r === 'object') ? r : {},
            }));
          
          setSearchResults(results);
          setCompleteness(response.completeness);
          // Use total_count from backend, but handle fallback for failed count queries
          let effectiveTotalCount = response.total_count;
          if (effectiveTotalCount === 0) {
            // If we got exactly the limit, there's likely more data
            effectiveTotalCount = results.length >= pageSize ? results.length * 100 : results.length;
          }
          setTotalCount(effectiveTotalCount);
          if (response.generated_sql) setGeneratedSql(response.generated_sql);
          // Set display type and column order from response (needed for | table queries)
          if (response.display_type) setDisplayType(response.display_type);
          setColumnOrder(response.column_order);
          setIsAggregateQuery(checkIfAggregateQuery(newQuery));
          // Always set histogram (even if empty) to ensure stale data is replaced
          setHistogramData(
            response.histogram && response.histogram.length > 0
              ? response.histogram.map((bucket: { time: string; count: number }) => ({
                  time: bucket.time,
                  count: bucket.count
                }))
              : []
          );
          
          // Capture search in notebook (if active)
          captureSearch(
            newQuery,
            'piped',
            response.total_count || results.length,
            response.execution_time_ms,
            apiTimeRange.start,
            apiTimeRange.end
          );
        } catch (err) {
          setSearchError(handleError(err, 'Unknown error'));
        } finally {
          setIsSearching(false);
          setHasSearched(true);
        }
      };
      
      runDrilldownSearch();
    }, 0);
  }, [query, timeRange, search, pageSize, updateUrl, beginRunScope, addToSearchHistory, refreshHistory, captureSearch, dataset]);

  // Toggle functions
  const toggleField = useCallback((field: string) => {
    setExpandedFields(prev => {
      const next = new Set(prev);
      if (next.has(field)) next.delete(field);
      else next.add(field);
      return next;
    });
  }, []);

  // Timeline zoom functions
  const handleZoomIn = useCallback(() => {
    const currentStart = timeRange.type === 'custom' && timeRange.start ? timeRange.start.getTime() : Date.now() - 24 * 60 * 60 * 1000;
    const currentEnd = timeRange.type === 'custom' && timeRange.end ? timeRange.end.getTime() : Date.now();
    const duration = currentEnd - currentStart;
    const center = currentStart + duration / 2;
    const newDuration = duration / 2;
    setTimeRange({ type: 'custom', start: new Date(center - newDuration / 2), end: new Date(center + newDuration / 2) });
    setShortUrlId(null);
  }, [timeRange]);

  const handleZoomOut = useCallback(() => {
    const currentStart = timeRange.type === 'custom' && timeRange.start ? timeRange.start.getTime() : Date.now() - 24 * 60 * 60 * 1000;
    const currentEnd = timeRange.type === 'custom' && timeRange.end ? timeRange.end.getTime() : Date.now();
    const duration = currentEnd - currentStart;
    const center = currentStart + duration / 2;
    const newDuration = duration * 2;
    setTimeRange({
      type: 'custom',
      start: new Date(Math.max(center - newDuration / 2, Date.now() - 365 * 24 * 60 * 60 * 1000)),
      end: new Date(Math.min(center + newDuration / 2, Date.now()))
    });
    setShortUrlId(null);
  }, [timeRange]);

  const handleResetZoom = useCallback(() => {
    setTimeRange({ type: 'preset', preset: 'Last hour', refreshedAt: Date.now() });
    setShortUrlId(null);
  }, []);

  // Handle single-bar click - now handled in mouseUp to distinguish from drag
  const handleTimelineClick = useCallback((_data: { activePayload?: Array<{ payload: { timestamp?: number } }> }) => {
    // Click is now handled in handleChartMouseUp to properly distinguish clicks from drags
  }, []);

  const handleChartMouseDown = useCallback((e: { activeLabel?: string | number }) => {
    if (e.activeLabel !== undefined) {
      setRefAreaLeft(e.activeLabel);
      setRefAreaRight(null);
      isDraggingRef.current = false; // Reset drag state
    }
  }, []);

  const handleChartMouseMove = useCallback((e: { activeLabel?: string | number }) => {
    if (refAreaLeft !== null && e.activeLabel !== undefined) {
      if (e.activeLabel !== refAreaLeft) {
        isDraggingRef.current = true; // User moved to a different bar = dragging
      }
      setRefAreaRight(e.activeLabel);
    }
  }, [refAreaLeft]);

  // Memoize the API time range to prevent unnecessary re-renders
  // This prevents TimelineVisualization from refetching prevalence data on every render
  // NAN-3299: the run's own bounds while the picker still holds the range the
  // run started with, so the chart, field panel and rarity fetches share the
  // window the rows were read from (a relative pick no longer becomes a fixed
  // range after each run).
  const apiTimeRange = useMemo(() => resolveRunTimeRange(runScope, timeRange), [runScope, timeRange]);
  // NAN-3254: while tailing, the chart's window slides to now so the buckets
  // the tail appends are not clipped. Same span as the picker. Only the plot
  // reads this; rarity / artifact fetches stay keyed on `apiTimeRange`.
  const timelinePlotRange = useMemo(() => {
    if (tailChartEndMs === null) return undefined;
    const spanMs = new Date(apiTimeRange.end).getTime() - new Date(apiTimeRange.start).getTime();
    if (!Number.isFinite(spanMs) || spanMs <= 0) return undefined;
    return { start: new Date(tailChartEndMs - spanMs).toISOString(), end: new Date(tailChartEndMs).toISOString() };
  }, [tailChartEndMs, apiTimeRange]);

  // NAN-3263: while the tail rolls the window, the picker says so instead of
  // showing the range the search started on.
  const tailRangeLabel = useMemo(() => {
    if (!tailActive || !timelinePlotRange) return undefined;
    const startMs = new Date(timelinePlotRange.start).getTime();
    const endMs = new Date(timelinePlotRange.end).getTime();
    const fmt = (ms: number) => new Date(ms).toISOString().slice(0, 19).replace('T', ' ');
    return {
      label: tailRollingRangeLabel(endMs - startMs),
      title: `${fmt(startMs)} – ${fmt(endMs)} UTC (live, rolling)`,
    };
  }, [tailActive, timelinePlotRange]);

  // Extract asset context from search results for prevalence scatter in asset mode
  const assetContext = useMemo(() => {
    if (displayType !== 'asset' || !searchResults.length) return undefined;
    const fields = searchResults[0]?.fields;
    if (fields?._display_type !== 'asset' || !fields?._asset_profile) return undefined;
    const profile = fields._asset_profile as { primary_identifier?: { field: string; value: string }; identities?: Record<string, unknown>[] };
    if (!profile.primary_identifier) return undefined;
    return {
      identifier_field: profile.primary_identifier.field,
      identifier_value: profile.primary_identifier.value,
      identities: (profile.identities || []) as Record<string, unknown>[],
    };
  }, [displayType, searchResults]);

  // Publish an early companion only after the rows have committed. A late
  // companion publishes directly; neither path replaces the chart twice.
  useEffect(() => {
    const split = splitHistogramRef.current;
    if (!split?.rowsIn || split.published || split.histogram === undefined
      || abortControllerRef.current?.signal.aborted
      || split.requestId !== currentRequestIdRef.current) return;
    split.published = true;
    setHistogramData(split.histogram);
    setSplitTiming(previous => previous ? {
      ...previous, completionMs: Math.round(Math.max(performance.now(), split.finishedAt ?? 0) - split.startedAt),
    } : previous);
  }, [searchResults]);

  // Timeline data: the API histogram; never invented from result rows
  const timelineData = useMemo(() => {
    // Determine if the time range spans multiple days (for label formatting)
    // Use apiTimeRange which has resolved start/end for both preset and custom ranges
    const rangeStart = new Date(apiTimeRange.start).getTime();
    const rangeEnd = new Date(apiTimeRange.end).getTime();
    const rangeDuration = rangeEnd - rangeStart;
    const spansDays = rangeDuration > 24 * 60 * 60 * 1000;
    const showSeconds = rangeDuration <= 2 * 60 * 60 * 1000; // Show seconds for ranges <= 2 hours

    // For asset view, build histogram from _asset_events with fixed-interval buckets
    if (displayType === 'asset' && searchResults.length > 0) {
      const assetEvents = searchResults[0]?.fields?._asset_events as Array<{ timestamp: string }> | undefined;
      if (assetEvents && assetEvents.length > 0) {
        // Calculate bucket interval based on time range (similar to API histogram)
        const bucketCount = Math.min(100, Math.max(20, Math.floor(rangeDuration / (5 * 60 * 1000))));
        const bucketInterval = Math.ceil(rangeDuration / bucketCount);

        // Initialize buckets across the entire time range
        const buckets = new Map<number, number>();
        for (let t = rangeStart; t <= rangeEnd; t += bucketInterval) {
          buckets.set(t, 0);
        }

        // Count events into buckets
        assetEvents.forEach(event => {
          const time = parseUTCTimestamp(event.timestamp).getTime();
          // Find the bucket this event belongs to
          const bucketStart = rangeStart + Math.floor((time - rangeStart) / bucketInterval) * bucketInterval;
          if (buckets.has(bucketStart)) {
            buckets.set(bucketStart, (buckets.get(bucketStart) || 0) + 1);
          }
        });

        return Array.from(buckets.entries())
          .sort((a, b) => a[0] - b[0])
          .map(([timestamp, events]) => ({
            time: formatTimelineLabel(new Date(timestamp), spansDays, showSeconds),
            timestamp,
            events
          }));
      }
    }

    // The server histogram (base-search events, also for `| stats`), a
    // timechart's `time_bucket` rows, or no timeline at all (NAN-3062).
    return buildSearchTimeline({
      histogramData: displayedHistogram(histogramData, timelineHold),
      results: searchResults,
      isAggregateQuery,
      spansDays,
      showSeconds,
    });
  }, [histogramData, timelineHold, searchResults, isAggregateQuery, apiTimeRange, displayType]);

  // Sum of histogram events - this is the true raw event count before aggregation/filtering
  const histogramEventCount = useMemo(() => {
    return timelineData.reduce((sum, d) => sum + d.events, 0);
  }, [timelineData]);

  const handleChartMouseUp = useCallback(() => {
    if (refAreaLeft) {
      if (isDraggingRef.current && refAreaRight && refAreaLeft !== refAreaRight) {
        // Drag selection - zoom to selected range
        const leftTs = Number(refAreaLeft);
        const rightTs = Number(refAreaRight);
        if (!isNaN(leftTs) && !isNaN(rightTs)) {
          const startTs = Math.min(leftTs, rightTs);
          const endTs = Math.max(leftTs, rightTs);
          // Calculate bucket size from timeline data to add proper end buffer
          const bucketMs = timelineData.length >= 2
            ? Math.abs(timelineData[1].timestamp - timelineData[0].timestamp)
            : 60 * 1000; // Default 1 minute
          setTimeRange({ type: 'custom', start: new Date(startTs), end: new Date(endTs + bucketMs) });
          setShortUrlId(null);
        }
      } else if (!isDraggingRef.current) {
        // Single bar click - zoom to that bucket's time range
        const clickedTs = Number(refAreaLeft);
        if (!isNaN(clickedTs)) {
          // Calculate bucket size from timeline data
          const bucketMs = timelineData.length >= 2
            ? Math.abs(timelineData[1].timestamp - timelineData[0].timestamp)
            : 60 * 1000; // Default 1 minute
          const start = new Date(clickedTs);
          const end = new Date(clickedTs + bucketMs);
          setTimeRange({ type: 'custom', start, end });
          setShortUrlId(null);
        }
      }
    }
    setRefAreaLeft(null);
    setRefAreaRight(null);
    isDraggingRef.current = false;
  }, [refAreaLeft, refAreaRight, timelineData]);

  // Synthetic CH helper columns leaking from the OCSF table — `*_unified`
  // coalesce internals (the NAN-1241 resolver maps logical names onto them;
  // analysts never address them directly) and the `event_bytes` sizing
  // metric. Not schema fields; keep them out of the field index.
  const isInternalHelperField = (name: string) =>
    name.endsWith('_unified') || name === 'event_bytes';

  // Field stats merge two scopes:
  // - server stats are authoritative for promoted fields aggregated across the
  //   full match set;
  // - visible-row stats discover canonical nested OCSF leaves which are not
  //   necessarily promoted/aggregated by the serving worker.
  //
  // Treating a non-empty server response as a complete inventory hid nearly
  // every `actor.*`, `device.*`, and `file.*` leaf from the rail even though
  // the expanded record rendered them. Server values win on collisions, but a
  // partial server response must never erase the visible event's field set.
  const fieldStats = useMemo<FieldStat[]>(() => {
    const authoritativeStats: FieldStat[] = serverFieldStats && serverFieldStats.length > 0
      ? serverFieldStats.map(field => {
        // Empty string is "field absent" (CH columns default to ''), not a
        // value — uniq()/topK() count it, which both surfaced "-" rows and
        // inflated the unique count by one. Strip it and rebase the counts
        // on actual values.
        const emptyCount = field.top_values
          .filter(([value]) => value === '')
          .reduce((sum, [, count]) => sum + count, 0);
        const nonEmpty = field.top_values.filter(([value]) => value !== '');
        const count = Math.max(0, field.count - emptyCount);
        const uniqueCount = Math.max(
          0,
          (field.cardinality ?? field.top_values.length) - (emptyCount > 0 ? 1 : 0),
        );
        return {
          field: field.name,
          count,
          uniqueCount,
          topValues: nonEmpty.map(([value, valueCount]) => ({
            value,
            count: valueCount,
            percentage: count > 0 ? Math.round((valueCount / count) * 100) : 0
          })),
          sampledRows: field.sampled_rows,
        };
        // Fields whose every value is empty are noise, and internal helper
        // columns aren't schema fields — don't surface either.
      }).filter(stat => stat.count > 0 && stat.topValues.length > 0 && !isInternalHelperField(stat.field))
      : [];

    if (!searchResults || searchResults.length === 0) return authoritativeStats;

    // Collect all flattened field values across all results
    const fieldValueCounts = new Map<string, Map<string, number>>();

    for (const result of searchResults) {
      if (result?.fields && typeof result.fields === 'object' && result.fields !== null) {
        const flattenedFields = flattenFieldsForStats(result.fields, isOcsf, promotedSchemaFields);

        for (const [field, rawValue] of flattenedFields) {
          if (isInternalHelperField(field)) continue;

          if (!fieldValueCounts.has(field)) {
            fieldValueCounts.set(field, new Map());
          }
          const valueCounts = fieldValueCounts.get(field)!;
          // Array-backed OCSF leaves (hashes, groups, data_sources, …) are
          // still fields. Count their scalar members individually rather than
          // dropping the whole field merely because multiple values survived
          // flattening. Nested objects should not remain after
          // `flattenEventFields`, but stay fail-closed if one does.
          const values = Array.isArray(rawValue) ? rawValue : [rawValue];
          for (const value of values) {
            if (value === null || value === undefined || value === '') continue;
            if (typeof value === 'object') continue;
            const valueStr = String(value);
            valueCounts.set(valueStr, (valueCounts.get(valueStr) || 0) + 1);
          }
          if (valueCounts.size === 0) fieldValueCounts.delete(field);
        }
      }
    }

    // Convert to FieldStat array
    const visibleStats = Array.from(fieldValueCounts.entries()).map(([field, valueCounts]) => {
      const totalCount = Array.from(valueCounts.values()).reduce((a, b) => a + b, 0);
      const topValues = Array.from(valueCounts.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .map(([value, count]) => ({
          value,
          count,
          percentage: totalCount > 0 ? Math.round((count / totalCount) * 100) : 0
        }));

      return {
        field,
        count: totalCount,
        uniqueCount: valueCounts.size,
        topValues
      };
    }).filter(stat => stat.count > 0 && stat.topValues.length > 0)
      .sort((a, b) => b.count - a.count); // Sort by count descending

    if (authoritativeStats.length === 0) return visibleStats;
    const merged = new Map(visibleStats.map((stat) => [stat.field, stat]));
    for (const stat of authoritativeStats) merged.set(stat.field, stat);
    return Array.from(merged.values()).sort((a, b) => b.count - a.count || a.field.localeCompare(b.field));
  }, [serverFieldStats, searchResults, isOcsf, promotedSchemaFields]);

  const availableFields = useMemo(() => {
    const fields = new Set<string>();
    fieldStats.forEach(stat => fields.add(stat.field));
    baseFieldStats.forEach(stat => fields.add(stat.field));
    return Array.from(fields).sort();
  }, [fieldStats, baseFieldStats]);

  // Register discovered fields (including ext fields) with the query tokenizer
  // so they get syntax highlighting in the search bar
  useEffect(() => {
    if (availableFields.length > 0) {
      registerDynamicFields(availableFields);
    }
  }, [availableFields]);

  // Fetch ext field names once authenticated so they're available for syntax
  // highlighting before the user runs their first search. Fire at most once per
  // mount — isAuthenticated can flip false->true during boot (token refresh), and
  // there's no need to re-seed the (slowly-changing) ext key list on each toggle.
  const extFieldsFetchedRef = useRef(false);
  useEffect(() => {
    // GET /api/fields/ext — tenant-scoped on the shared profile.
    if (!isAuthenticated || extFieldsFetchedRef.current) return;
    extFieldsFetchedRef.current = true;
    api.getExtFieldNames()
      .then((names: string[]) => {
        if (names.length > 0) {
          registerDynamicFields(names);
        }
      })
      .catch(() => {
        // Best-effort: ext-field highlighting is optional. Permit a retry on the
        // next auth change if this attempt failed.
        extFieldsFetchedRef.current = false;
      });
  }, [isAuthenticated]);

  // Auto-run effect - when navigating to search with run=true (e.g., from AI suggestions)
  const lastAutoRunQueryRef = useRef<string | null>(null);
  useEffect(() => {
    // Only auto-run if the run param is set and we have a query that hasn't been auto-run yet
    if (urlAutoRun && urlQuery && lastAutoRunQueryRef.current !== urlQuery) {
      lastAutoRunQueryRef.current = urlQuery;
      setFieldsPanelVisible(true);

      // Enable AI mode if coming from notebook AI suggestion
      if (urlAiMode) {
        setAiResponse('Query from AI suggestion. Use the refinement input below to modify this query.');
        setShowAiThinking(true);
      }

      // NAN-1451: honor the time window the deep-link specifies, not the stale
      // `timeRange` state. `setTimeRange` from the URL-sync effect hasn't applied
      // yet when this fires, and this effect doesn't depend on `timeRange`, so
      // passing the state value ran the search over whatever range was previously
      // active — e.g. the asset-view redirect (`…&run=true&time=Last 4 hours`)
      // executed over the old wide range and tripped the `| asset` 6h cap while
      // the picker showed "Last 4 hours". Fall back to state only when the URL
      // names no window (AI-suggestion `run=true` links).
      const autoRunTimeRange: TimeRangeValue = readTimeRangeParams(searchParams) ?? timeRange;

      // Small delay to ensure state is ready
      const timer = setTimeout(() => {
        handleSearch(1, false, urlQuery, queryMode, autoRunTimeRange, true); // NAN-1602: URL-driven (passive) load → use cache + badge
        // Clear the run and ai params from URL after execution
        const params = new URLSearchParams(searchParams);
        params.delete('run');
        params.delete('ai');
        // NAN-3299: our own cleanup write — not navigation to re-run.
        prevUrlRef.current = params.toString();
        setSearchParams(params, { replace: true });
      }, 100);
      return () => clearTimeout(timer);
    }
  }, [urlAutoRun, urlQuery, urlAiMode]);

  // Load results from a completed async job (e.g. from ActiveSearchesPanel or notification link)
  const lastJobIdRef = useRef<string | null>(null);
  useEffect(() => {
    if (!urlJobId || lastJobIdRef.current === urlJobId) return;
    lastJobIdRef.current = urlJobId;
    let cancelled = false;

    (async () => {
      try {
        setIsSearching(true);
        setFieldsPanelVisible(true);
        const status = await api.getSearchJob(urlJobId, {
          isCancelled: () => cancelled,
          onUnavailable: () => setSearchError({ code: AUTHORITY_UNAVAILABLE, message: AUTHORITY_NOTICE, warningSeverity: 'info' }),
          onRecovered: () => setSearchError(previous => previous?.code === AUTHORITY_UNAVAILABLE ? null : previous),
        });
        if (cancelled) return;

        if (status.status === 'completed' && status.result) {
          setDurableResultCursor(null);
          processAsyncJobResult(
            status.result,
            status.result.generated_sql || urlQuery || 'Loaded from job',
            timeRange,
            queryMode as 'piped' | 'sql',
            false,
          );
          setIsSearching(false);
          setHasSearched(true);
        } else if (status.status === 'completed' && status.durable_result) {
          if (status.task_kind === 'prevalence_export_v1') {
            const download = await api.downloadSearchJob(urlJobId);
            saveDurableDownload(download.blob, download.filename);
            setIsSearching(false);
            setHasSearched(true);
            queryClient.invalidateQueries({ queryKey: ['search-jobs'] });
            return;
          }
          const page = status.durable_result.pages === 0
            ? { page: 0, pages: 0, page_rows: status.durable_result.page_rows, row_offset: 0, total_rows: 0, rows: [] }
            : await api.getSearchJobResultPage(urlJobId, 0);
          const restoredTyped = processTypedDurableJobResult(
            status,
            page,
            status.query || urlQuery || '',
            timeRange,
          );
          if (restoredTyped) {
            setIsSearching(false);
            setHasSearched(true);
            queryClient.invalidateQueries({ queryKey: ['search-jobs'] });
            if (status.task_kind === 'lateral_v1') return; // The typed restoration already replaced the job URL.
          } else {
            processAsyncJobResult(
              {
                results: page.rows,
                total_count: page.total_rows,
                total_count_exact: true, // NAN-2550: synthesised locally; this count is the whole set.
                execution_time_ms: status.progress?.elapsed_ms ?? 0,
                fields: [],
                warnings: durableResultWarnings(status.durable_result, page.pages),
              },
              status.query || urlQuery || 'Loaded from durable job',
              timeRange,
              queryMode as 'piped' | 'sql',
              false,
              status.dataset,
              page.row_offset,
            );
            setDurableResultCursor({
              jobId: urlJobId,
              pages: page.pages,
              pageRows: status.durable_result.page_rows,
              loadedPage: page.page,
              rowOffset: page.row_offset,
            });
            setIsSearching(false);
            setHasSearched(true);
          }
        } else if (status.status === 'queued' || status.status === 'running') {
          // Job is still in progress — start polling
          setAsyncJobId(urlJobId);
          setAsyncJobStatus(status.status);
          startAsyncJobPolling(urlJobId, urlQuery || '', timeRange, queryMode as 'piped' | 'sql', false);
        } else if (status.status === 'failed') {
          setIsSearching(false);
          const jobErrMsg = status.error || 'Search job failed';
          setSearchError({ code: 'JOB_FAILED', message: jobErrMsg });
          requestQueryCorrection('JOB_FAILED', jobErrMsg, urlQuery || query);
        } else {
          setIsSearching(false);
        }
      } catch (err) {
        if (cancelled || (err instanceof Error && err.name === 'AbortError')) return;
        setIsSearching(false);
        const is404 = err instanceof Error && err.message.includes('404');
        if (is404) {
          setSearchError({ code: 'JOB_EXPIRED', message: 'Search job is no longer available' });
          queryClient.invalidateQueries({ queryKey: ['search-jobs'] });
        } else {
          setSearchError({ code: 'JOB_FAILED', message: 'Could not load search job' });
        }
      }
      // Clean job_id from URL to prevent re-loading on navigation
      searchParams.delete('job_id');
      setSearchParams(searchParams, { replace: true });
    })();
    return () => {
      cancelled = true;
      if (lastJobIdRef.current === urlJobId) lastJobIdRef.current = null;
    };
  }, [urlJobId]); // eslint-disable-line react-hooks/exhaustive-deps

  // Effects
  useEffect(() => {
    if (urlShortId && !hasSearched) {
      if (!searchSurface.storedShortLinks) {
        // GET /api/search/shared/{id} is not served on this profile — say so
        // instead of retrying.
        setSearchError({
          code: 'UNAVAILABLE',
          message: 'Stored short links are not available on this tenant yet. Use "Copy link" to share the full URL.',
        });
      } else {
        loadSharedSearch(urlShortId);
      }
    } else if (urlQuery && !hasSearched && !urlAutoRun) {
      // Show fields panel since we have a query to execute
      setFieldsPanelVisible(true);
      
      // GET /api/search/explanation — only where the profile serves the
      // cache (see SearchSurface.explanationCache).
      if (searchSurface.explanationCache) {
        getQueryExplanation(urlQuery)
          .then((explanation) => {
          // Populate the AI panel with cached explanation
          if (explanation.reasoning_steps && explanation.reasoning_steps.length > 0) {
            setAiReasoningSteps(explanation.reasoning_steps.map(step => ({
              step_type: step.step_type as 'parse_request' | 'source_discovery' | 'field_analysis' | 'query_generation' | 'validation',
              title: step.title,
              description: step.description,
              details: step.details,
            })));
          }
          if (explanation.explanation) {
            setAiResponse(explanation.explanation);
          }
          if (explanation.fields_used) {
            setAiFieldsUsed(explanation.fields_used);
          }
          if (explanation.generated_sql) {
            setAiGeneratedSql(explanation.generated_sql);
          }
          if (explanation.complexity) {
            setAiComplexity(explanation.complexity);
          }
          if (explanation.suggested_time_range) {
            setAiSuggestedTimeRange(explanation.suggested_time_range);
          }
          if (explanation.natural_language_prompt) {
            setNaturalLanguageQuery(explanation.natural_language_prompt);
          }
          // Keep AI panel collapsed by default (user can expand to see details)
          setShowAiThinking(false);
          })
          .catch(() => {
            // No cached explanation - that's fine, just run the search
          });
      }
      
      const timer = setTimeout(() => handleSearch(1, false, urlQuery, queryMode, timeRange, true), 100); // NAN-1602: URL-driven (passive) load → use cache + badge
      return () => clearTimeout(timer);
    }
  }, []);

  // Sync state from URL when browser back/forward is used
  const prevUrlRef = useRef(searchParams.toString());
  // NAN-3883: the URL this effect last saw from the router. React Router
  // delivers a location inside startTransition, so after the page's own
  // updateUrl (which already moved prevUrlRef to the new URL) urgent renders
  // still carry the OLD searchParams. This effect re-runs on every render
  // (handleSearch changes identity each render), and read that lag as
  // back/forward: it restored the previous query and re-ran it, then restored
  // the new one and ran it again — three /api/search per click in production (two
  // of the new query, one of the previous). Only a location the router has
  // actually delivered can be navigation.
  const seenUrlRef = useRef(searchParams.toString());
  useEffect(() => {
    const currentUrlStr = searchParams.toString();
    if (currentUrlStr === seenUrlRef.current) return;
    seenUrlRef.current = currentUrlStr;
    // A job link is restored by the fenced artifact loader above. Treating
    // its absent query as back-navigation can erase a just-restored graph.
    if (searchParams.has('job_id')) {
      prevUrlRef.current = currentUrlStr;
      return;
    }
    // Only process if URL actually changed (back/forward navigation)
    if (currentUrlStr === prevUrlRef.current) return;
    prevUrlRef.current = currentUrlStr;
    
    const currentUrlQuery = searchParams.get('q') || '';
    const currentUrlMode = (searchParams.get('mode') as 'piped' | 'sql' | 'natural') || 'piped';
    // NAN-1825: restore the dataset from the URL too — back-nav across a
    // dataset boundary (logs ↔ spans/metrics/risk) must re-run against the
    // dataset that search actually targeted.
    const rawUrlDataset = searchParams.get('dataset');
    const urlDataset: import('@/lib/api/types').SearchDataset = isSearchDataset(rawUrlDataset)
      ? rawUrlDataset
      : 'logs';
    
    // Build time range from URL
    const historyTimeRange: TimeRangeValue = readTimeRangeParams(searchParams)
      ?? { type: 'preset', preset: 'Last hour' };
    
    // Normalize mode (convert old 'natural' to 'piped')
    const normalizedMode = !searchSurface.rawSql || currentUrlMode === 'natural'
      ? 'piped'
      : currentUrlMode as 'piped' | 'sql';
    
    // Check if this is a meaningful state change
    const queryChanged = currentUrlQuery !== query;
    const modeChanged = normalizedMode !== queryMode;
    const timeChanged = JSON.stringify(historyTimeRange) !== JSON.stringify(timeRange);
    const datasetChanged = urlDataset !== dataset;

    // Always restore state from URL if there's a meaningful change, regardless of hasSearched
    if (queryChanged || modeChanged || timeChanged || datasetChanged) {
      // URL changed from back/forward - restore state and re-search
      // Set flag BEFORE updating state to prevent timeRange effect from also triggering
      isRestoringFromHistory.current = true;

      // Update state
      setQuery(currentUrlQuery);
      setQueryMode(normalizedMode);
      setTimeRange(historyTimeRange);
      setDataset(urlDataset);
      
      // Show fields panel if there's a query
      if (currentUrlQuery.trim()) {
        setFieldsPanelVisible(true);
      }
      
      // If this was a natural language query from URL, put it in the natural language input
      if (currentUrlMode === 'natural') {
        setNaturalLanguageQuery(currentUrlQuery);
        setQuery(''); // Clear the main query since it was natural language
      }
      
      // Also update the prevTimeRangeRef to prevent the timeRange effect from triggering
      prevTimeRangeRef.current = historyTimeRange;
      
      // If there's a query in the URL, check cache first, then fall back to search
      if (currentUrlQuery.trim() && currentUrlMode !== 'natural') {
        const cacheKey = buildCacheKey(currentUrlQuery, historyTimeRange, normalizedMode, urlDataset);
        // NAN-3884: a relative range in the URL (`time=Last 7 days`) means
        // "re-resolve against now", so back-nav re-runs it, as it did when
        // the URL always carried fixed bounds. Only a fixed window restores
        // from cache.
        const cached = searchSurface.browserResultCache && historyTimeRange.type === 'custom'
          ? searchResultCache.get(cacheKey)
          : undefined;
        if (cached && (Date.now() - cached.cachedAt) < CACHE_TTL_MS) {
          // Restore from cache — instant back-navigation
          // NAN-3884: the restored rows' window is this URL's, so the meta row
          // and later pages read these bounds, not the previous run's.
          const restoredScope: SearchRunScope = { timeRange: historyTimeRange, range: toApiTimeRange(historyTimeRange) };
          runScopeRef.current = restoredScope;
          setRunScope(restoredScope);
          setLiveRun(false); // NAN-1602: passive restore → views use cache + badge, not a live re-fetch
          setSearchResults(cached.results);
          setHistogramData(cached.histogramData);
          setServerFieldStats(cached.serverFieldStats);
          // NAN-1509: restore the reduced/full flag the cached stats were computed
          // with, so a cached broad search keeps its "Show all fields" teaser +
          // NAN-1503 auto-fetch (was hardcoded false → cached broad searches lost
          // the affordance). Null (stats never landed) → not reduced.
          setFieldStatsReduced(cached.fieldStatsReduced ?? false);
          setTotalCount(cached.totalCount);
          setTotalCountExact(cached.totalCountExact);
          setPagingComplete(cached.totalCountExact && cached.results.length >= cached.totalCount);
          setExecutionTimeMs(cached.executionTimeMs);
          setCompleteness(cached.completeness);
          setDisplayType(cached.displayType);
          setColumnOrder(cached.columnOrder);
          setGeneratedSql(cached.generatedSql);
          setQueryCostScore(cached.costScore);
          setExecutedQuery(cached.executedQuery);
          setIsAggregateQuery(cached.isAggregateQuery);
          setPeakRowsScanned(cached.peakRowsScanned ?? 0);
          setFieldsPanelExpanded(!cached.isAggregateQuery);
          userToggledFieldsPanel.current = false;
          setHasSearched(true);
          setSearchError(null);
          setCachedResultsTimestamp(cached.cachedAt);
          setTimeout(() => {
            isRestoringFromHistory.current = false;
          }, 50);
        } else {
          // Cache miss or expired — re-fetch. Pass the URL dataset explicitly:
          // the setDataset above hasn't re-rendered into the handleSearch
          // closure this timeout captured (NAN-1825).
          if (cached) searchResultCache.delete(cacheKey);
          setTimeout(() => {
            handleSearch(1, false, currentUrlQuery, normalizedMode, historyTimeRange, true, urlDataset); // NAN-1602: URL-restore miss (passive) → use cache + badge
          }, 50);
        }
      } else {
        // Back-navigated to an empty /search (or a natural-language URL we
        // can't replay). Without this, the URL reverts but the previously
        // rendered results stick on screen, so users need a second back click
        // to escape the page.
        setSearchResults([]);
        setCompleteness(undefined);
        setHistogramData([]);
        setServerFieldStats(null);
        setFieldStatsReduced(false);
        setTotalCount(0);
        setPeakRowsScanned(0);
        setExecutionTimeMs(null);
        setDisplayType(undefined);
        setColumnOrder(undefined);
        setGeneratedSql(null);
        setQueryCostScore(null);
        setExecutedQuery('');
        setIsAggregateQuery(false);
        setHasSearched(false);
        setSearchError(null);
        setLimitWarningDismissed(false);
        setCachedResultsTimestamp(null);
        setTimeout(() => {
          isRestoringFromHistory.current = false;
        }, 50);
      }
    }
  }, [searchParams, query, queryMode, timeRange, dataset, handleSearch, isSearchDataset, searchSurface.rawSql, searchSurface.browserResultCache]);

  useEffect(() => {
    // Trigger search when time range changes (both custom and preset)
    // Skip if we're restoring from browser history (that effect handles the search)
    if (isRestoringFromHistory.current) {
      prevTimeRangeRef.current = timeRange;
      return;
    }
    // Skip if AI query generation is in-flight — the AI completion handler
    // will auto-run the search with the generated query and current timeRange
    if (aiLoading) {
      prevTimeRangeRef.current = timeRange;
      return;
    }
    // Use JSON comparison to detect actual value changes
    const prevStr = JSON.stringify(prevTimeRangeRef.current);
    const currStr = JSON.stringify(timeRange);
    if (prevStr !== currStr && tailActive && !tailFollowsRange(timeRange, Date.now(), tailInterval)) {
      // NAN-2836: the analyst picked a fixed range that ends in the past. The
      // tail re-anchors its window at "now" on every tick, so leaving it on
      // would slide their pick away on the next tick. Stop and say so. A
      // relative pick keeps the tail running on the new window (the search
      // below re-arms it).
      setTailActive(false);
      setTailStoppedForRange(true);
    }
    if (prevStr !== currStr && hasSearched) {
      handleSearch();
    }
    prevTimeRangeRef.current = timeRange;
  }, [timeRange]);

  // Track previous prevalence value to detect changes
  const prevPrevalenceRef = useRef(prevalenceMax);
  useEffect(() => {
    // Trigger search when prevalence filter changes (only if we have previous results)
    if (prevPrevalenceRef.current !== prevalenceMax && hasSearched) {
      handleSearch();
    }
    prevPrevalenceRef.current = prevalenceMax;
  }, [prevalenceMax, hasSearched, handleSearch]);

  useEffect(() => {
    return () => { if (abortControllerRef.current) abortControllerRef.current.abort(); };
  }, []);

  // Threshold for the "narrow your query" warning. For aggregate queries
  // `totalCount` is the post-aggregation output size, so we fall back to the
  // peak `rows_scanned` reported by streaming progress events.
  const warningRowCount = isAggregateQuery ? peakRowsScanned : displayTotalCount;
  const showLimitWarning =
    warningRowCount >= 1_000_000 && !isSearching && hasSearched && !limitWarningDismissed;
  const showErrorOrWarning = !!searchError || showLimitWarning;

  // NAN-1598: for two-phase modes that adopt the phase-2 reporter, drive the
  // footer from the phase-2 status (the real view fetch) instead of the
  // throwaway marker query, and suppress "Query complete" until the view
  // reports done (phase2 == null || loading => keep showing the spinner).
  const footerGated = displayType != null && PHASE2_REPORTING_MODES.has(displayType);
  const footerIsSearching = isSearching || (footerGated && (phase2 == null || phase2.loading));
  const footerExecutionTimeMs = footerGated
    ? (phase2 && !phase2.loading ? (phase2.executionTimeMs ?? null) : null)
    : executionTimeMs;
  const footerTotalCount = footerGated ? (phase2?.totalCount ?? 0) : displayTotalCount;
  // NAN-3884: the picker keeps a relative pick relative; the meta row says
  // which absolute window this run actually covered (viewer's timezone).
  // The live tail rolls the window, and the picker already says so.
  const runTimeWindowLabel = runScope && !tailActive
    ? formatTimeWindowLabel(runScope.timeRange, runScope.range)
    : undefined;

  return (
    <div className={`search-console-page flex flex-col gap-2.5 w-full min-w-0 overflow-x-hidden md:[overflow-x:clip] ${hlWipe ? 'hl-wipe' : ''}`}>
      {/* Demo onboarding: sample queries */}
      {!hasSearched && (
        <SearchDemoHint onRunQuery={(q) => { setQuery(q); handleSearch(1, false, q); }} />
      )}

      {/* Main Query Card + error drawer wrapper (keeps them flush despite parent space-y) */}
      <div>
      <Card className={`search-console-card relative border transition-colors duration-300 ease-out ${
        showAiSuggestion || aiLoading || showAiThinking
          ? 'bg-gradient-to-r from-ai-bg to-ai-bg-subtle border-ai-border'
          : 'bg-card border-border'
      } ${
        showErrorOrWarning
          ? 'rounded-t-lg rounded-b-none'
          : 'rounded-lg'
      }`}>
        <CardContent className="p-3 px-3.5 flex flex-col gap-2.5">
          <div className="search-console-header flex flex-wrap items-center gap-2 whitespace-nowrap font-mono text-[11px] tracking-[0.16em] uppercase font-semibold leading-none mb-1">
            <span className="text-muted-foreground">Search Console</span>
            <span className="text-muted-foreground/40">›</span>
            <span className="text-primary search-console-mode">
              {queryMode === 'sql' ? 'SQL' : <span className="normal-case">nPL</span>} Pipeline
            </span>
            <span className="text-muted-foreground/40 hidden md:inline">›</span>
            <span className="hidden md:inline text-muted-foreground search-console-time">UTC {new Date().toLocaleTimeString('en-US', { timeZone: 'UTC', hour: '2-digit', minute: '2-digit', hour12: false })}</span>
          </div>

          {/* NAN-1555: the dataset selector moved into the footer chip row as a
              compact dropdown card (DatasetSelector), next to Rarity — it no
              longer consumes a full segmented row above the search bar. */}

          {/* Unified search bar with auto-detect query language.
              NOTE: the old "pivt — natural language in, query out" banner
              was replaced by the NATURAL LANGUAGE badge that sits above
              the input border inside SearchQueryInput. */}
          <div className="flex flex-col md:flex-row md:items-start gap-2.5">
            {/* Search input that expands */}
            <SearchQueryInput
              query={query}
              onQueryChange={(q) => {
                setQuery(q);
                setSearchError(null);
                // Auto-detect query mode
                const trimmed = q.trim().toUpperCase();
                if (trimmed.startsWith('SELECT') || trimmed.startsWith('WITH') || trimmed.startsWith('INSERT') || trimmed.startsWith('UPDATE') || trimmed.startsWith('DELETE')) {
                  if (canRawSql) {
                    setQueryMode('sql');
                  } else {
                    setQueryMode('piped');
                    setSearchError({
                      code: 'PERMISSION_DENIED',
                      message: isOcsf
                        ? 'Raw SQL is intentionally unavailable on the tenant-pinned OCSF lake path. Use nPL.'
                        : 'Raw SQL queries require the search:sql permission. Contact your administrator.',
                    });
                  }
                } else {
                  setQueryMode('piped');
                }
                // Clear AI state when user manually types a structured query (has operators)
                // But don't clear if AI is programmatically setting the query
                if (/[=|<>!]/.test(q) && !isAiSettingQueryRef.current) {
                  setShowAiThinking(false);
                  setAiResponse(null);
                  setAiError(null);
                  setAiConversationHistory([]);
                }
              }}
              queryMode={queryMode}
              onSearch={handleSearch}
              onAiSearch={capabilities.melod && melodStatus?.connected ? () => handleAskMelod(query) : undefined}
              aiMode={showAiSuggestion || aiLoading || showAiThinking}
              searchHistory={searchHistory}
              historyEnabled={historyEnabled}
              onToggleHistoryEnabled={toggleHistoryEnabled}
              onClearAllHistory={clearSearchHistory}
              savedSearches={savedSearches?.map(s => ({ id: s.id, name: s.name, query: s.query, query_mode: s.query_mode })) || []}
              pinnedSearchIds={pinnedSearchIds}
              onSelectHistoryItem={(q, mode) => {
                setQuery(q);
                setQueryMode(mode);
              }}
              timeRange={apiTimeRange}
              isOcsf={isOcsf}
            />
            {/* Time picker and search button - stacked below on mobile, inline on desktop */}
            <div className="flex-shrink-0 flex w-full md:w-auto gap-2.5">
              <DateTimeRangePicker
                value={timeRange}
                onChange={setTimeRange}
                variant="search"
                displayOverride={tailRangeLabel?.label}
                displayTitle={tailRangeLabel?.title}
              />
              <Button
                className="search-console-action rounded-md h-[34px] w-[34px] p-0 border bg-primary hover:bg-primary/90 border-border text-primary-foreground transition-colors duration-300 ease-out"
                onClick={() => showAiSuggestion && capabilities.melod ? handleAskMelod(query) : handleSearch()}
                disabled={isSearching || aiLoading}
              >
                {isSearching || aiLoading ? (
                  <LoadingIcon className="w-[15px] h-[15px]" />
                ) : showAiSuggestion ? (
                  <PivtIcon className="w-[15px] h-[15px]" />
                ) : (
                  <SearchIcon className="w-[15px] h-[15px]" />
                )}
              </Button>
            </div>
            {isSearching && (
              <Button variant="outline" className="search-console-action border-destructive/50 text-destructive hover:bg-destructive/10 rounded-md h-[34px] w-[34px] p-0 self-start" onClick={handleStopSearch}>
                <Square className="w-[13px] h-[13px]" />
              </Button>
            )}
          </div>

          {/* Tree view breadcrumb - shows when viewing a tree with a previous query to return to */}
          {isTreeView && previousQuery && (
            <div className="flex items-center gap-2 mt-2 animate-in fade-in slide-in-from-top-1 duration-200">
              <button
                onClick={() => {
                  setQuery(previousQuery);
                  handleSearch(1, false, previousQuery, queryMode, timeRange);
                }}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-muted-foreground hover:text-foreground bg-muted/50 hover:bg-muted rounded-lg border border-border/50 transition-colors"
              >
                <ArrowLeft className="w-3 h-3" />
                <span>Return to query</span>
              </button>
              <span className="text-xs text-muted-foreground font-mono truncate max-w-md">
                {previousQuery}
              </span>
              <Badge variant="outline" className="border-emerald-500/30 text-emerald-400 text-xs">
                <GitBranch className="w-3 h-3 mr-1" />
                Tree Trace
              </Badge>
            </div>
          )}

          {/* AI Thinking Panel - shows when AI is processing or has response */}
          {(aiLoading || aiResponse || aiError) && (
            <div className={`mt-1 rounded-md border ${aiError ? 'border-red-500/20 bg-red-500/5' : 'border-ai-border/60 bg-ai-bg-subtle'}`}>
              {/* Collapsed header */}
              <button
                onClick={() => setShowAiThinking(!showAiThinking)}
                className={`w-full px-3 py-2 flex items-center justify-between text-xs ${aiError ? 'text-red-400 hover:bg-red-500/10' : 'text-ai hover:bg-ai-bg/60'} ${showAiThinking ? 'rounded-t-md' : 'rounded-md'} transition-colors`}
              >
                <div className="flex items-center gap-2">
                  <PivtIcon className="w-3.5 h-3.5" />
                  <span className="font-medium">
                    {aiLoading ? 'Analyzing your question...' : aiError ? 'Error' : 'Query Generated'}
                  </span>
                  {aiLoading && <LoadingIcon className="w-3 h-3" />}
                </div>
                {showAiThinking ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
              </button>

              {/* Expanded content */}
              {showAiThinking && (
                <div className={`px-3 pb-3 ${aiError ? '' : ''}`}>
                  {aiLoading ? (
                    <div className="space-y-2 pt-2">
                      <div className="text-xs text-foreground/70 space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="text-ai">→</span> Parsing natural language query
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="text-ai">→</span> Searching for matching data sources
                        </div>
                        <div className="flex items-center gap-2 animate-pulse">
                          <span className="text-ai">→</span> Generating optimized query...
                        </div>
                      </div>
                    </div>
                  ) : aiError ? (
                    <div className="text-sm text-red-400 whitespace-pre-wrap pt-2">{aiError}</div>
                  ) : aiResponse ? (
                    <div className="space-y-3 pt-2">
                      {/* Reasoning Steps */}
                      {aiReasoningSteps.length > 0 && (
                        <div className="space-y-2">
                          {aiReasoningSteps.map((step, i) => (
                            <div key={i} className="flex items-start gap-2 text-xs">
                              <div className="flex-shrink-0 mt-0.5">
                                {step.step_type === 'source_discovery' ? (
                                  <FileSearch className="w-3.5 h-3.5 text-ai" />
                                ) : step.step_type === 'field_analysis' ? (
                                  <Database className="w-3.5 h-3.5 text-ai" />
                                ) : step.step_type === 'validation' ? (
                                  <CircleCheck className="w-3.5 h-3.5 text-ai" />
                                ) : (
                                  <Zap className="w-3.5 h-3.5 text-ai" />
                                )}
                              </div>
                              <div className="flex-1 min-w-0">
                                <span className="text-ai font-medium">{step.title}:</span>{' '}
                                <span className="text-foreground/70">{step.description}</span>
                              </div>
                            </div>
                          ))}
                        </div>
                      )}

                      {/* Metadata badges */}
                      <div className="flex flex-wrap items-center gap-2">
                        {aiComplexity && (
                          <div className="flex items-center gap-1.5 px-2 py-1 bg-ai-bg rounded-lg">
                            <Layers className="w-3 h-3 text-ai" />
                            <span className="text-xs text-foreground/70">{aiComplexity}</span>
                          </div>
                        )}
                        {aiSuggestedTimeRange && (
                          <div className="flex items-center gap-1.5 px-2 py-1 bg-ai-bg rounded-lg">
                            <Clock className="w-3 h-3 text-ai" />
                            <span className="text-xs text-foreground/70">{aiSuggestedTimeRange}</span>
                          </div>
                        )}
                      </div>

                      {/* Expandable details */}
                      {(aiGeneratedSql || aiFieldsUsed.length > 0) && (
                        <button
                          onClick={(e) => { e.stopPropagation(); setShowAiDetails(!showAiDetails); }}
                          className="flex items-center gap-1 text-xs text-ai hover:text-ai-muted transition-colors"
                        >
                          {showAiDetails ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
                          {showAiDetails ? 'Hide' : 'Show'} technical details
                        </button>
                      )}

                      {/* Technical details */}
                      {showAiDetails && (
                        <div className="border-t border-ai-border mt-2 pt-3 space-y-3">
                          {aiFieldsUsed.length > 0 && (
                            <div>
                              <div className="flex items-center gap-2 text-xs text-ai mb-2">
                                <Database className="w-3 h-3" />
                                <span className="font-medium">Fields Used</span>
                              </div>
                              <div className="flex flex-wrap gap-1.5">
                                {aiFieldsUsed.map((field, i) => (
                                  <span key={i} className="px-2 py-0.5 bg-ai-bg text-ai text-xs rounded-md font-mono">
                                    {field}
                                  </span>
                                ))}
                              </div>
                            </div>
                          )}
                          {aiGeneratedSql && (
                            <div>
                              <div className="flex items-center justify-between mb-2">
                                <div className="flex items-center gap-2 text-xs text-ai">
                                  <Code className="w-3 h-3" />
                                  <span className="font-medium">Generated SQL</span>
                                </div>
                                <button
                                  onClick={(e) => { e.stopPropagation(); navigator.clipboard.writeText(aiGeneratedSql); }}
                                  className="text-xs text-ai hover:text-ai-muted flex items-center gap-1"
                                >
                                  <Copy className="w-3 h-3" />
                                  Copy
                                </button>
                              </div>
                              <pre className="p-3 bg-ai-bg rounded-lg text-xs text-foreground/80 font-mono overflow-x-auto whitespace-pre-wrap">
                                {aiGeneratedSql}
                              </pre>
                            </div>
                          )}
                        </div>
                      )}

                      {/* Refinement input — final section of the panel, blends into the parent container */}
                      <div className="border-t border-ai-border/40 pt-3 mt-1">
                        <div className="flex items-center gap-2 mb-2">
                          <MessageSquare className="w-3.5 h-3.5 text-ai" />
                          <span className="text-xs font-medium text-ai">Refine your query</span>
                          {aiConversationHistory.length > 1 && (
                            <span className="text-[10px] text-muted-foreground ml-auto">
                              {aiConversationHistory.length} turns
                            </span>
                          )}
                        </div>
                        <div className="flex items-center gap-2 p-2 bg-background/60 rounded-md border border-ai-border/40 focus-within:border-ai/70 focus-within:ring-1 focus-within:ring-ai/20 transition-all">
                          <input
                            type="text"
                            value={refinementQuery}
                            onChange={(e) => setRefinementQuery(e.target.value)}
                            onKeyDown={(e) => {
                              if (e.key === 'Enter' && refinementQuery.trim()) {
                                handleAskMelod(refinementQuery, true);
                              }
                            }}
                            placeholder="e.g., &quot;now show stats by hour&quot; or &quot;filter to just errors&quot;..."
                            className="flex-1 bg-transparent text-sm text-foreground placeholder:text-muted-foreground/50 focus:outline-none"
                          />
                          <button
                            onClick={() => refinementQuery.trim() && handleAskMelod(refinementQuery, true)}
                            disabled={!refinementQuery.trim()}
                            className={`px-3 py-1.5 text-xs rounded-md transition-all flex items-center gap-1.5 ${
                              refinementQuery.trim()
                                ? 'bg-ai text-ai-foreground hover:bg-ai/90 shadow-sm'
                                : 'bg-muted text-muted-foreground cursor-not-allowed'
                            }`}
                          >
                            <CornerDownLeft className="w-3 h-3" />
                            Refine
                          </button>
                        </div>
                      </div>
                    </div>
                  ) : null}
                </div>
              )}
            </div>
          )}

          {/* Footer chip row — mockup-style chips */}
          <div className="flex items-center gap-2 font-mono text-[11px] text-muted-foreground tracking-wide flex-wrap">
            {/* Saved queries — opens the new SavedQueriesPalette */}
            {hasPermission('search:view') && (
              <button
                type="button"
                onClick={() => setSavedQueriesOpen(true)}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md border border-border bg-foreground/[0.02] text-muted-foreground hover:border-border/80 hover:text-foreground transition-colors whitespace-nowrap shrink-0"
              >
                <LayoutGrid className="w-[11px] h-[11px]" />
                Saved queries
              </button>
            )}

            {/* Tail -f with interval dropdown */}
            {hasSearched && query?.trim() && (
              <div
                className={`inline-flex items-stretch rounded-md border transition-colors whitespace-nowrap shrink-0 overflow-hidden ${
                  tailActive
                    ? 'border-emerald-600/60 bg-emerald-600/15 text-emerald-800 dark:border-emerald-500/40 dark:bg-emerald-500/10 dark:text-emerald-400'
                    : 'border-border bg-foreground/[0.02] text-muted-foreground hover:border-border/80'
                }`}
              >
                <button
                  type="button"
                  onClick={() => setTailActive(prev => !prev)}
                  title={tailActive
                    ? 'Tailing: the selected window follows now. A relative range change keeps tailing; a fixed past range stops it.'
                    : 'Re-run on an interval with the selected window ending at now'}
                  className={`inline-flex items-center gap-1.5 pl-2.5 pr-2 py-1 ${!tailActive ? 'hover:text-foreground' : ''}`}
                >
                  {tailActive ? (
                    <span className="relative flex w-[9px] h-[9px] items-center justify-center">
                      <span className="absolute inset-0 rounded-full bg-emerald-600/60 dark:bg-emerald-400/60 animate-ping" />
                      <span className="relative w-[5px] h-[5px] rounded-full bg-emerald-600 dark:bg-emerald-400" />
                    </span>
                  ) : (
                    <Menu className="w-[11px] h-[11px]" />
                  )}
                  <span>tail -f</span>
                  <span
                    className={`font-mono tabular-nums text-[10.5px] tracking-tight rounded-sm px-1 py-px ${
                      tailActive ? 'bg-emerald-700/15 text-emerald-900 dark:bg-emerald-400/15 dark:text-emerald-300' : 'text-muted-foreground/70'
                    }`}
                  >
                    {TAIL_INTERVALS.find(t => t.ms === tailInterval)?.label ?? '15s'}
                  </span>
                </button>
                <span aria-hidden className={`w-px my-1 ${tailActive ? 'bg-emerald-700/35 dark:bg-emerald-500/30' : 'bg-border'}`} />
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <button
                      type="button"
                      aria-label="Tail interval"
                      className={`px-1.5 flex items-center ${!tailActive ? 'hover:text-foreground' : ''}`}
                    >
                      <ChevronDown className="w-[10px] h-[10px]" />
                    </button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent side="bottom" sideOffset={6} align="end" className="min-w-[140px] p-1">
                    <DropdownMenuLabel className="px-2 py-1 text-[11px] tracking-normal normal-case text-muted-foreground font-normal">Refresh every</DropdownMenuLabel>
                    {TAIL_INTERVALS.map(({ label, ms }) => (
                      <DropdownMenuItem
                        key={ms}
                        onClick={() => { setTailInterval(ms); if (!tailActive) setTailActive(true); }}
                        className="gap-1.5 px-2 py-1 text-[12px]"
                      >
                        <span className="font-mono tabular-nums flex-1">{label}</span>
                        {tailInterval === ms && <DropdownMenuShortcut>✓</DropdownMenuShortcut>}
                      </DropdownMenuItem>
                    ))}
                  </DropdownMenuContent>
                </DropdownMenu>
              </div>
            )}
            {!tailActive && tailStoppedForRange && hasSearched && query?.trim() && (
              <span
                role="status"
                className="font-mono text-[10.5px] text-muted-foreground whitespace-nowrap shrink-0"
                title="A fixed range that ends in the past cannot be tailed. Pick a relative range and turn tail -f back on to follow it."
              >
                tail stopped · fixed range
              </span>
            )}

            {/* Separator only when something follows it — an empty Save/Share
                slot must not leave an orphan dot next to the next chip. */}
            {(canSave || canShare) && (
              <span aria-hidden className="mx-1.5 w-1 h-1 rounded-full bg-border shrink-0" />
            )}

            {/* Save */}
            {canSave && (
              <button
                type="button"
                onClick={() => setSaveDialogOpen(true)}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md border border-border bg-foreground/[0.02] text-muted-foreground hover:border-border/80 hover:text-foreground transition-colors whitespace-nowrap shrink-0"
              >
                <Save className="w-[11px] h-[11px]" />
                Save
              </button>
            )}

            {/* Share dropdown */}
            {canShare && (
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <button
                    type="button"
                    className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md border border-border bg-foreground/[0.02] text-muted-foreground hover:border-border/80 hover:text-foreground transition-colors whitespace-nowrap shrink-0"
                  >
                    <Share2 className="w-[11px] h-[11px]" />
                    Share
                  </button>
                </DropdownMenuTrigger>
                <DropdownMenuContent side="bottom" sideOffset={6} className="min-w-[220px] p-1">
                  <DropdownMenuLabel className="px-2 py-1 text-[11px] tracking-normal normal-case text-muted-foreground font-normal">
                    Share this query
                  </DropdownMenuLabel>
                  <DropdownMenuItem onSelect={() => copyShareableUrl()} className="gap-1.5 px-2 py-1 text-[12px]">
                    {copiedUrl ? <Check className="w-[13px] h-[13px] text-green-400" /> : <Copy className="w-[13px] h-[13px]" />}
                    <span>{copiedUrl ? 'Copied!' : 'Copy link'}</span>
                    <DropdownMenuShortcut>⌘L</DropdownMenuShortcut>
                  </DropdownMenuItem>
                  {searchSurface.storedShortLinks && (
                    <DropdownMenuItem
                      onSelect={() => createAndCopyShortUrl()}
                      disabled={isCreatingShortUrl || !query?.trim()}
                      className="gap-1.5 px-2 py-1 text-[12px]"
                    >
                      {isCreatingShortUrl ? <LoadingIcon className="w-[13px] h-[13px]" /> : <Link2 className="w-[13px] h-[13px]" />}
                      <span>Copy short URL</span>
                      <DropdownMenuShortcut>⌘⇧L</DropdownMenuShortcut>
                    </DropdownMenuItem>
                  )}
                </DropdownMenuContent>
              </DropdownMenu>
            )}

            {/* Event Stream restore — only when chart is collapsed */}
            {timelineCollapsed && hasSearched && (
              <>
                <span aria-hidden className="mx-1.5 w-1 h-1 rounded-full bg-border shrink-0" />
                <button
                  type="button"
                  onClick={() => setTimelineCollapsed(false)}
                  className="inline-flex items-center gap-2 pl-2 pr-2.5 py-1 rounded-md border border-border bg-foreground/[0.02] hover:border-border/80 hover:text-foreground text-muted-foreground transition-colors shrink-0 whitespace-nowrap"
                >
                  <Activity className="w-[12px] h-[12px] text-primary/70" />
                  <span>Event Stream</span>
                  {typeof histogramEventCount === 'number' && histogramEventCount > 0 && (
                    <span className="text-muted-foreground/60 tabular-nums">
                      {histogramEventCount.toLocaleString()}
                    </span>
                  )}
                  <ChevronDown className="w-[10px] h-[10px] rotate-180" />
                </button>
              </>
            )}

            {/* Dataset selector — compact dropdown card (NAN-1555). Sits next to
                Rarity in the footer chip row instead of a full segmented row. */}
            {datasetChoices.length > 1 && (
              <>
                <span aria-hidden className="mx-1.5 w-1 h-1 rounded-full bg-border shrink-0" />
                <DatasetSelector value={dataset} onChange={setDataset} disabled={isSearching} />
              </>
            )}

            {/* Prevalence slider (piped mode only) — compact */}
            {queryMode === 'piped' && (
              <>
                <span aria-hidden className="mx-1.5 w-1 h-1 rounded-full bg-border shrink-0" />
                <PrevalenceSlider
                  value={prevalenceMax}
                  onChange={setPrevalenceMax}
                  disabled={isSearching}
                />
              </>
            )}

            {/* Short URL badge (when one exists for this query) */}
            {shortUrlId && (
              <button
                type="button"
                onClick={async () => {
                  const shortUrl = `${window.location.origin}/search?s=${shortUrlId}`;
                  await navigator.clipboard.writeText(shortUrl);
                  setCopiedShortUrl(true);
                  setTimeout(() => setCopiedShortUrl(false), 2000);
                }}
                className="inline-flex items-center gap-1.5 px-2 py-1 rounded-md border border-primary/25 bg-primary/8 text-primary hover:bg-primary/14 transition-colors shrink-0 whitespace-nowrap"
                title="Click to copy short URL"
              >
                {copiedShortUrl ? <Check className="w-[11px] h-[11px]" /> : <Link2 className="w-[11px] h-[11px]" />}
                <span className="font-mono tabular-nums">{shortUrlId}</span>
              </button>
            )}

            <div className="flex-1" />

            {/* Active query-mode pill — read-only indicator that links to
                User Settings → Query mode (NAN-???). Replaces the old per-page
                NPL/SQL slider; default mode now lives in user preferences and
                is changed there, not ad-hoc per search. SQL pill is only
                rendered when the user actually has search:sql; otherwise the
                NPL pill is the only state and clicking it still deep-links to
                settings (locked-state messaging lives there). */}
            {!searchSurface.rawSql ? (
              <span
                title="nPL only — raw SQL is not served by the tenant lake"
                className="inline-flex items-center gap-1 h-[22px] px-2 rounded-md border border-border bg-foreground/[0.03] text-[10.5px] text-primary font-mono tracking-[0.08em] font-semibold shrink-0"
              >
                nPL
              </span>
            ) : (
              <RouterLink
                to="/settings/user#query"
                title={
                  queryMode === 'sql'
                    ? 'Advanced (SQL) mode — set in user settings'
                    : 'Set default query mode in user settings'
                }
                className={cn(
                'inline-flex items-center gap-1 h-[22px] px-2 rounded-md border text-[10.5px] font-mono tracking-[0.08em] font-semibold transition-colors shrink-0',
                queryMode === 'sql'
                  // Advanced (SQL): elevated visibility — burnt-orange tint
                  // signals "more power, more responsibility" without
                  // crossing into error-red territory.
                  ? 'border-[color-mix(in_srgb,var(--accent-orange)_45%,transparent)] bg-[color-mix(in_srgb,var(--accent-orange)_12%,transparent)] text-[var(--accent-orange)] hover:bg-[color-mix(in_srgb,var(--accent-orange)_18%,transparent)]'
                  : 'border-border bg-foreground/[0.03] text-primary hover:border-primary/40 hover:bg-primary/8',
                )}
              >
                <span>{queryMode === 'sql' ? 'SQL' : 'nPL'}</span>
                <Settings2
                  className={cn(
                  'w-[10px] h-[10px]',
                  queryMode === 'sql'
                    ? 'text-[color-mix(in_srgb,var(--accent-orange)_70%,transparent)]'
                    : 'text-muted-foreground/70',
                  )}
                />
              </RouterLink>
            )}

            {/* More menu — contextual extras (Inspect SQL, Promote to Rule,
                Pin, Running jobs). Badge dot appears on the trigger when
                there are active async search jobs. */}
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <button
                  type="button"
                  aria-label="More"
                  className="relative w-6 h-6 flex items-center justify-center rounded-md border border-border bg-foreground/[0.02] text-muted-foreground hover:border-border/80 hover:text-foreground transition-colors shrink-0"
                >
                  <MoreHorizontal className="w-3 h-3" />
                  {activeJobCount > 0 && (
                    <span
                      aria-label={`${activeJobCount} active job${activeJobCount === 1 ? '' : 's'}`}
                      className="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full bg-primary ring-1 ring-card"
                    />
                  )}
                </button>
              </DropdownMenuTrigger>
              <DropdownMenuContent side="bottom" sideOffset={6} align="end" className="min-w-[200px] p-1">
                <DropdownMenuItem
                  onClick={() => setJobsModalOpen(true)}
                  className="gap-1.5 px-2 py-1 text-[12px]"
                >
                  <Activity className="w-[13px] h-[13px]" />
                  <span>Running jobs</span>
                  {activeJobCount > 0 && (
                    <span className="ml-auto rounded-sm bg-primary/15 text-primary text-[9.5px] px-1 font-semibold tabular-nums">
                      {activeJobCount}
                    </span>
                  )}
                </DropdownMenuItem>
                {(queryMode === 'piped' || (hasSearched && query?.trim())) && (
                  <DropdownMenuSeparator className="-mx-1 my-1 h-px bg-border" />
                )}
                {queryMode === 'piped' && (
                  <DropdownMenuItem onClick={handleShowSql} disabled={explaining} className="gap-1.5 px-2 py-1 text-[12px]">
                    {explaining ? <LoadingIcon className="w-[13px] h-[13px]" /> : <Code className="w-[13px] h-[13px]" />}
                    <span>{showSql ? 'Hide SQL' : 'Inspect SQL'}</span>
                  </DropdownMenuItem>
                )}
                {hasPermission('detections:create') && queryMode === 'piped' && query?.trim() && (
                  <DropdownMenuItem
                    onClick={() => navigate(`/rules/editor/new?query=${encodeURIComponent(query)}`)}
                    className="gap-1.5 px-2 py-1 text-[12px]"
                  >
                    <Shield className="w-[13px] h-[13px]" />
                    <span>Promote to Rule</span>
                  </DropdownMenuItem>
                )}
                {hasSearched && query?.trim() && (
                  <DropdownMenuItem onClick={() => setShowAddToDashboardDialog(true)} className="gap-1.5 px-2 py-1 text-[12px]">
                    <LayoutDashboard className="w-[13px] h-[13px]" />
                    <span>Pin to Dashboard</span>
                  </DropdownMenuItem>
                )}
                {hasSearched && query?.trim() && (
                  <DropdownMenuItem
                    onClick={() =>
                      setSchedulePreset({ source_type: 'search', source_query: query, defaultName: '' })
                    }
                    className="gap-1.5 px-2 py-1 text-[12px]"
                  >
                    <CalendarClock className="w-[13px] h-[13px]" />
                    <span>Schedule report</span>
                  </DropdownMenuItem>
                )}
              </DropdownMenuContent>
            </DropdownMenu>
          </div>

          {/* Saved queries palette — net-new UI that replaces the Search Hub
              drawer for saved/shared queries. See SavedQueriesPalette.tsx. */}
          <SavedQueriesPalette
            open={savedQueriesOpen}
            onOpenChange={setSavedQueriesOpen}
            savedSearches={savedSearches || []}
            sharedSearches={sharedSearches || []}
            currentUserId={user?.id}
            onSelectQuery={(q, mode) => {
              setQuery(q);
              if (mode) setQueryMode(mode);
              handleSearch(1, false, q, mode ?? queryMode, timeRange);
            }}
            onScheduleQuery={(q) => {
              setSavedQueriesOpen(false);
              setSchedulePreset({
                source_type: 'search',
                source_query: q.query,
                saved_query_id: typeof q.id === 'number' ? q.id : undefined,
                defaultName: q.name,
              });
            }}
          />

          {/* Schedule report (NAN-1793) — cron a saved query into CSV/HTML artifacts */}
          {schedulePreset && (
            <ScheduleReportDialog
              open={!!schedulePreset}
              onOpenChange={(o) => {
                if (!o) setSchedulePreset(null);
              }}
              preset={schedulePreset}
            />
          )}

          {/* Search jobs modal — opened from the More (...) menu */}
          <SearchJobsModal
            open={jobsModalOpen}
            onOpenChange={setJobsModalOpen}
            onLoadJob={(jobId) => {
              navigate(`${searchPagePath}?job_id=${jobId}`);
              setJobsModalOpen(false);
            }}
            onCancelJob={(jobId) => {
              api.cancelSearchJob(jobId).catch(() => {});
              if (jobId === asyncJobId) {
                clearAsyncJob();
                setIsSearching(false);
              }
            }}
          />

          {/* Save Query Dialog — shadcn redesign (NAN-374), ported from
              design-ref/shadcn/query-block.jsx SaveQueryDialog. */}
          {saveDialogOpen && (
            <div
              className="fixed inset-0 z-[100] flex items-start justify-center pt-[12vh] bg-black/50 backdrop-blur-[2px]"
              onClick={() => setSaveDialogOpen(false)}
              onKeyDown={(e) => { if (e.key === 'Escape') setSaveDialogOpen(false); }}
            >
              <div
                onClick={(e) => e.stopPropagation()}
                className="w-[480px] max-w-[92%] bg-card border border-border rounded-xl shadow-[0_40px_100px_rgba(0,0,0,0.6)] overflow-hidden"
              >
                <div className="px-4 py-3 border-b border-border flex items-center gap-2">
                  <Save className="w-[14px] h-[14px] text-primary" />
                  <span className="text-[13px] font-semibold text-foreground">Save query</span>
                  <button
                    type="button"
                    className="ml-auto text-muted-foreground cursor-pointer text-[16px] leading-none hover:text-foreground"
                    onClick={() => setSaveDialogOpen(false)}
                    aria-label="Close"
                  >
                    ×
                  </button>
                </div>
                <div className="px-4 py-4 space-y-3.5">
                  <div>
                    <label className="block font-mono text-[10px] tracking-[0.14em] uppercase text-muted-foreground font-semibold mb-1.5">Name</label>
                    <input
                      autoFocus
                      value={saveSearchName}
                      onChange={(e) => setSaveSearchName(e.target.value)}
                      placeholder="e.g. Failed console logins"
                      className="w-full h-9 px-3 bg-background border border-border-2 rounded-md text-[13px] outline-none focus:border-primary/50 focus:ring-1 focus:ring-primary/25"
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' && saveSearchName.trim() && !saving) {
                          e.preventDefault();
                          handleSaveSearch();
                        }
                      }}
                    />
                  </div>
                  <div>
                    <label className="block font-mono text-[10px] tracking-[0.14em] uppercase text-muted-foreground font-semibold mb-1.5">
                      Description <span className="text-muted-foreground/60 normal-case tracking-normal">(optional)</span>
                    </label>
                    <textarea
                      value={saveSearchDescription}
                      onChange={(e) => setSaveSearchDescription(e.target.value)}
                      rows={2}
                      placeholder="Short explanation for your team"
                      className="w-full px-3 py-2 bg-background border border-border-2 rounded-md text-[13px] outline-none focus:border-primary/50 focus:ring-1 focus:ring-primary/25 resize-none"
                    />
                  </div>
                  <div className="flex items-center justify-end">
                    <label className="inline-flex items-center gap-2 cursor-pointer">
                      <Checkbox
                        checked={saveSearchShared}
                        onCheckedChange={(checked) => setSaveSearchShared(checked === true)}
                        className="h-3.5 w-3.5"
                      />
                      <span className="text-[12px] text-foreground/80">Share with team</span>
                    </label>
                  </div>
                </div>
                <div className="px-4 py-3 border-t border-border flex items-center justify-end gap-2">
                  <button
                    type="button"
                    onClick={() => setSaveDialogOpen(false)}
                    className="h-8 px-3 rounded-md text-[12px] text-foreground/80 hover:bg-foreground/5"
                  >
                    Cancel
                  </button>
                  <button
                    type="button"
                    disabled={!saveSearchName.trim() || saving}
                    onClick={handleSaveSearch}
                    className={`h-8 px-3 rounded-md text-[12px] font-semibold inline-flex items-center gap-1.5 ${
                      saveSearchName.trim() && !saving
                        ? 'bg-primary text-primary-foreground hover:bg-primary/90'
                        : 'bg-foreground/5 text-muted-foreground cursor-not-allowed'
                    }`}
                  >
                    {saving && <LoadingIcon className="w-3.5 h-3.5" />}
                    Save query
                  </button>
                </div>
              </div>
            </div>
          )}
        </CardContent>
        
      </Card>

      {/* Error/warning drawer - slides out from bottom of search card */}
      <div
        className="grid transition-[grid-template-rows,opacity] duration-300 ease-out"
        style={{
          gridTemplateRows: showErrorOrWarning ? '1fr' : '0fr',
          opacity: showErrorOrWarning ? 1 : 0,
        }}
      >
        <div className="overflow-hidden min-h-0">
        {/* Severity drives a faint background wash + the icon tint only —
            no border line, no bold label color. Reads as "informational"
            without competing with results below. */}
        <div
          className="px-5 py-2.5 rounded-b-xl border-t border-border/40 flex items-center gap-3"
          style={{
            background: `color-mix(in srgb, ${
              searchError?.code === 'PARSE_ERROR' || searchError?.code === 'EMPTY_QUERY' || searchError?.code === 'VALIDATION_ERROR'
                ? 'var(--destructive)'
                : searchError?.warningSeverity === 'info'
                ? 'var(--primary)'
                : 'var(--warning)'
            } 4%, var(--card))`,
          }}
        >
          {/* Icon-only severity indicator: the glyph + color carries the
              severity; the precise label ("Info" / "Warning" / "Syntax Error" /
              …) is a hover tooltip on the wrapping span (a bare <svg> title is
              unreliable). Same label mapping for every kind. */}
          <span
            className="flex-shrink-0 flex items-center"
            title={
              searchError?.code === 'PARSE_ERROR' ? 'Syntax Error'
              : searchError?.code === 'EMPTY_QUERY' ? 'Empty Query'
              : searchError?.code === 'VALIDATION_ERROR' ? 'Query Blocked'
              : searchError?.warningSeverity === 'info' ? 'Info'
              : 'Warning'
            }
          >
            {searchError?.warningSeverity === 'info' ? (
              <Info
                className="w-4 h-4"
                style={{ color: 'color-mix(in srgb, var(--primary) 70%, transparent)' }}
              />
            ) : (
              <AlertTriangle
                className="w-4 h-4"
                style={{
                  color: `color-mix(in srgb, ${
                    searchError?.code === 'PARSE_ERROR' || searchError?.code === 'EMPTY_QUERY' || searchError?.code === 'VALIDATION_ERROR'
                      ? 'var(--destructive)'
                      : 'var(--warning)'
                  } 70%, transparent)`,
                }}
              />
            )}
          </span>
          <div className="flex-1 min-w-0">
            {searchError ? (
              <>
                {(() => {
                  const aiSuggestion = searchError.details?.suggestions?.find(s => s.description && s.replacement);
                  if (aiSuggestion) {
                    return (
                      <div className="flex items-center gap-2 flex-wrap">
                        <PivtIcon className="w-3.5 h-3.5 text-violet-400 flex-shrink-0" />
                        <span className="text-sm text-muted-foreground">Did you mean</span>
                        <button
                          onClick={() => { applySuggestion(aiSuggestion.replacement); setSearchError(null); }}
                          className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-mono bg-violet-500/10 hover:bg-violet-500/20 border border-violet-500/30 text-violet-300 rounded-md transition-colors"
                        >
                          {aiSuggestion.replacement}
                        </button>
                        {aiSuggestion.unverified && (
                          <Badge
                            variant="outline"
                            className="px-1.5 py-0 text-[10px] font-mono uppercase tracking-wide text-amber-400 border-amber-500/40"
                            title="This correction could not be validated against the schema — review before running."
                          >
                            unverified
                          </Badge>
                        )}
                        <span className="text-xs text-muted-foreground/60">{aiSuggestion.description}</span>
                      </div>
                    );
                  }
                  return (
                    <>
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-sm text-muted-foreground">{searchError.message}</span>
                        {searchError.code === 'JOB_FAILED' && !isSearching && (
                          <button
                            type="button"
                            onClick={() => handleSearch(1, false)}
                            className="inline-flex items-center gap-1 px-2 py-0.5 text-xs border border-border rounded-md hover:bg-muted transition-colors"
                          >
                            <RotateCcw className="w-3 h-3" />
                            Retry
                          </button>
                        )}
                        {searchError.message.includes("host not in this tenant's inputlookup allowlist") && (
                          <RouterLink className="text-xs text-primary underline" to="/settings/integrations/lookup-url-allowlist">Manage Lookup URL allowlist</RouterLink>
                        )}
                      </div>
                      {searchError.details?.suggestions && searchError.details.suggestions.length > 0 && (
                        <div className="flex flex-wrap items-center gap-2 mt-2">
                          {searchError.details.suggestions.map((suggestion, index) => (
                            suggestion.replacement ? (
                              <button
                                key={index}
                                onClick={() => { applySuggestion(suggestion.replacement); setSearchError(null); }}
                                className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-mono bg-muted/50 hover:bg-muted border border-border rounded-md transition-colors"
                              >
                                <Zap className="w-3 h-3 text-amber-400" />
                                {suggestion.replacement}
                              </button>
                            ) : suggestion.description ? (
                              <span key={index} className="text-xs text-muted-foreground">{suggestion.description}</span>
                            ) : null
                          ))}
                        </div>
                      )}
                      {isCorrectingQuery && (
                        <div className="flex items-center gap-1.5 mt-2 text-xs text-muted-foreground">
                          <LoadingIcon className="w-3 h-3 text-violet-400" />
                          AI analyzing query...
                        </div>
                      )}
                    </>
                  );
                })()}
              </>
            ) : isAggregateQuery ? (
              <span className="text-sm text-muted-foreground">
                <span className="text-amber-400 font-medium">{peakRowsScanned.toLocaleString()}+ rows scanned</span>
                {' '}&mdash; consider narrowing your time range or adding filters before the aggregate.
              </span>
            ) : (
              <span className="text-sm text-muted-foreground">
                <span className="text-amber-400 font-medium">{displayTotalCount.toLocaleString()}+ hits</span>
                {' '}&mdash; consider narrowing your time range, adding filters, or using{' '}
                <code className="text-xs font-mono text-emerald-400 bg-muted/50 px-1 py-0.5 rounded">| stats count by field</code>
                {' '}to aggregate.
              </span>
            )}
          </div>
          <button
            onClick={() => { if (searchError) { setSearchError(null); } else { setLimitWarningDismissed(true); } }}
            className="text-muted-foreground hover:text-foreground flex-shrink-0 p-0.5 rounded hover:bg-muted/50 transition-colors"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
        </div>
      </div>
      </div>

      {/* SQL Preview */}
      {showSql && queryMode === 'piped' && generatedSql && (
        <Card className="search-console-subpanel bg-card border rounded-xl">
          <CardContent className="p-4">
            <p className="text-xs font-mono uppercase tracking-[0.22em] text-muted-foreground mb-2">Compiled SQL</p>
            <code className="text-sm text-green-700 dark:text-green-400 font-mono whitespace-pre-wrap">{generatedSql}</code>
          </CardContent>
        </Card>
      )}

      {/* AI Query Best Practices Suggestions */}
      {(queryReviewSuggestions.length > 0 || isReviewingQuery) && (
        <div className="flex items-start gap-3 px-4 py-3 bg-violet-500/5 border border-violet-500/20 rounded-xl text-sm">
          <Sparkles className="w-4 h-4 text-violet-400 mt-0.5 flex-shrink-0" />
          <div className="flex-1 min-w-0">
            {isReviewingQuery ? (
              <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                <LoadingIcon className="w-3 h-3 text-violet-400" />
                Reviewing query for optimizations...
              </div>
            ) : (
              <>
                <span className="text-xs font-medium text-violet-400">Query tuning</span>
                <div className="flex flex-col gap-2 mt-1.5">
                  {queryReviewSuggestions.map((suggestion, index) => (
                    <div key={index} className="flex items-start gap-2">
                      <span className="text-xs text-muted-foreground mt-0.5">{suggestion.description}</span>
                      <button
                        onClick={() => { setQuery(suggestion.optimized_query); setQueryReviewSuggestions([]); }}
                        className="inline-flex items-center gap-1 px-2 py-0.5 text-xs font-mono bg-violet-500/10 hover:bg-violet-500/20 border border-violet-500/30 rounded transition-colors flex-shrink-0"
                      >
                        <Zap className="w-3 h-3 text-violet-400" />
                        Apply
                      </button>
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>
          <button
            onClick={() => setQueryReviewSuggestions([])}
            className="text-muted-foreground hover:text-foreground flex-shrink-0 p-0.5 rounded hover:bg-muted/50 transition-colors"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      <div className="search-workspace-shell">
        {/* Hide timeline for visualization types that render their own charts
            or don't benefit from a histogram (lateral DAG has no per-bucket
            event density to show; cloud overview/dossier ship their own
            activity timeline). */}
        {!hasStatsPipeline(stripComments(executedQuery)) && !isTreeView && displayType !== 'timechart' && displayType !== 'ranked_bar' && displayType !== 'flow' && displayType !== 'asset' && displayType !== 'cloud' && displayType !== 'lateral' && displayType !== 'services' && displayType !== 'service' && displayType !== 'trace' && displayType !== 'metric' && displayType !== 'retro' && displayType !== 'baseline' && (
        <TimelineVisualization
          timelineData={timelineData}
          eventCount={histogramEventCount}
          collapsed={timelineCollapsed}
          onToggleCollapsed={() => setTimelineCollapsed(!timelineCollapsed)}
          chartType={chartType}
          onChartTypeChange={(type) => { localStorage.setItem('nanosiem-chart-type', type); setChartType(type); }}
          onZoomIn={handleZoomIn}
          onZoomOut={handleZoomOut}
          onResetZoom={handleResetZoom}
          onTimelineClick={handleTimelineClick}
          refAreaLeft={refAreaLeft}
          refAreaRight={refAreaRight}
          onMouseDown={handleChartMouseDown}
          onMouseMove={handleChartMouseMove}
          onMouseUp={handleChartMouseUp}
          // NAN-2557: this panel is fed the paged set, so it keeps the paged
          // set's own count below; the tail sum belongs to the results chrome.
          results={searchResults}
          hasSearched={hasSearched}
          onArtifactFilter={(artifact, artifactType, _ts) => {
            // Route through handleDrilldown so the artifact filter reuses the
            // proven stats-drill path (deferred setQuery → updateUrl → search).
            // Calling handleSearch synchronously here raced the URL-sync effect,
            // which restored the pre-drill query and clobbered the filter.
            // Escape like the field=value drilldown builder — a log-derived
            // artifact with `"`/`\` must not break out of the quoted comparison.
            const esc = nplQuotedBody(artifact);
            const artifactQuery =
              artifactType === 'hash'
                ? isOcsf
                  ? `(file.hashes.value="${esc}" OR process.file.hashes.value="${esc}" OR actor.process.file.hashes.value="${esc}")`
                  : `(file_hash="${esc}" OR process_hash="${esc}")`
                : isOcsf
                  // Must cover every DOMAIN_PATHS surface discovery groups by
                  // (inWindowObservation.ts) — omitting one (url.hostname was
                  // missing) makes a dot discovered only on that path drill
                  // into a query that matches nothing.
                  ? `(dst_endpoint.hostname="${esc}" OR query.hostname="${esc}" OR http_request.url.hostname="${esc}" OR url.hostname="${esc}")`
                  : `(dest_host="${esc}" OR query="${esc}" OR url_domain="${esc}")`;
            // NAN-2361: land on a table, not raw JSON per row — an analyst
            // pivoting off a rarity dot wants who/where/when at a glance
            // across every occurrence, not one expanded blob at a time. All
            // three artifact paths are separate columns (rather than one
            // coalesced column) so it's visible at a glance which path
            // matched on a given row — the OR predicate means only one of
            // them is ever populated per row.
            // Hash columns include a name/path pair for EACH of the 3 hash
            // paths queried: `file.name`/`file.path` (plain file-activity
            // match, no `process` object at all), `process.name`/
            // `process.file.path` (process-execution match), and
            // `actor.process.name`/`actor.process.file.path` (module/DLL-load
            // match — verified live: class_name "Module Activity" carries the
            // hash + name under `actor.process.file`, with a NULL top-level
            // `process`, since the actor process is what loaded the module).
            // Whichever OR arm matched determines which pair is non-empty.
            const tableCommand =
              artifactType === 'hash'
                ? '| table time, metadata.log_source, device.hostname, actor.user.name, file.name, file.path, process.name, process.file.path, actor.process.name, actor.process.file.path, file.hashes.value, process.file.hashes.value, actor.process.file.hashes.value'
                : '| table time, metadata.log_source, device.hostname, actor.user.name, dst_endpoint.hostname, query.hostname, http_request.url.hostname, url.hostname, dst_endpoint.ip';
            handleDrilldown({ _rawClause: artifactQuery, _tableCommand: tableCommand });
          }}
          assetContext={assetContext}
          timeWindow="24h"
          resultCount={totalCount}
          query={executedQuery}
          timeRange={apiTimeRange}
          plotRange={timelinePlotRange}
        />
        )}

        {/* Field Index collapse — now rendered as a beacon pill inside the
            Results header via SearchResults' fieldsCollapsed prop. */}

        {/* Mobile Fields button - always visible on mobile when field data available */}
        {isMobile && fieldsPanelVisible && !isTreeView && displayType !== 'timechart' && displayType !== 'ranked_bar' && displayType !== 'flow' && displayType !== 'cloud' && displayType !== 'lateral' && displayType !== 'services' && displayType !== 'service' && displayType !== 'trace' && displayType !== 'metric' && displayType !== 'retro' && displayType !== 'baseline' && (
          <div className="animate-in fade-in slide-in-from-top-1 duration-300 px-4 py-3">
            <button
              onClick={() => setMobileFieldsOpen(true)}
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-muted/50 hover:bg-muted text-muted-foreground hover:text-foreground transition-all border border-transparent hover:border-border"
              title="Show field index"
            >
              <span className="search-console-section-header"><List />Field Index</span>
              {fieldStats.length > 0 && (
                <Badge variant="outline" className="h-4 px-1.5 text-[10px] border-border">
                  {fieldStats.length}
                </Badge>
              )}
            </button>
          </div>
        )}

        {/* Analyze mode — replaces the normal fields + results area with
            a full-page LLM analysis view when active. */}
        {showAnalyze && (
          <div className="flex-1 flex flex-col min-h-0 min-w-0">
            <AnalyzeView
              query={query}
              queryMode={queryMode}
              results={displayResults}
              totalCount={displayTotalCount}
              timeRange={timeRange}
              histogram={histogramData}
              onBack={() => setAnalyzeActive(false)}
              onRunQuery={(q) => {
                setQuery(q);
                setAnalyzeActive(false);
                handleSearch(1, false, q, queryMode);
              }}
            />
          </div>
        )}

        {/* Fields panel + Results area - Fields panel hidden for full-width visualizations */}
        {!showAnalyze && (() => {
          const showFieldsPanel = fieldsPanelVisible && !isTreeView &&
            displayType !== 'timechart' && displayType !== 'ranked_bar' && displayType !== 'flow' && displayType !== 'asset' && displayType !== 'cloud' && displayType !== 'lateral' && displayType !== 'services' && displayType !== 'service' && displayType !== 'trace' && displayType !== 'metric' && displayType !== 'baseline';
          return (
            <div className={`flex w-full min-w-0 ${showFieldsPanel && fieldsPanelExpanded ? 'gap-2.5' : ''}`} style={{ minHeight: 0 }}>
              {/* Fields Panel - hidden on mobile */}
              <div className={`hidden md:block transition-all duration-500 ease-in-out flex-shrink-0 ${
                showFieldsPanel && fieldsPanelExpanded
                  ? 'w-[230px] opacity-100 translate-x-0'
                  : 'w-0 opacity-0 -translate-x-full overflow-hidden'
              }`}>
                {showFieldsPanel && fieldsPanelExpanded && (
                  <div className="sticky top-0">
                    <FieldsPanel
                      fieldStats={fieldStats}
                      baseFieldStats={baseFieldStats}
                      isAggregateQuery={isAggregateQuery}
                      showBaseFields={showBaseFields}
                      onToggleShowBaseFields={() => setShowBaseFields(!showBaseFields)}
                      expandedFields={expandedFields}
                      onToggleField={toggleField}
                      onAddToQuery={addToQuery}
                      onGroupBy={groupByField}
                      isExpanded={fieldsPanelExpanded}
                      onToggleExpanded={() => { userToggledFieldsPanel.current = true; setFieldsPanelExpanded(!fieldsPanelExpanded); }}
                      isLoading={fieldStatsLoading && fieldStats.length === 0}
                      isLoadingMore={fieldStatsLoading && fieldStats.length > 0}
                      // NAN-3299: scope to the executed search, not the editor text —
                      // a keystroke must not refetch the panel's ext names / values.
                      query={executedQuery || query}
                      timeRange={apiTimeRange}
                      onFetchFieldValues={(field, q, start, end) =>
                        // NAN-1559: drill-in must use the dataset the displayed
                        // results were executed with (snapshotted at search time),
                        // NOT the live selector — switching datasets without
                        // re-running would otherwise resolve the field against the
                        // wrong table.
                        fetchSearchFieldValues({ field, query: q, start, end, limit: 100, dataset: lastFieldStatsRequestRef.current?.dataset ?? dataset })
                      }
                      isReducedFieldSet={fieldStatsReduced}
                      onLoadAllFields={loadAllFieldStats}
                    />
                  </div>
                )}
              </div>

              {/* Results Area */}
              <div className="flex-1 min-w-0">
                {/* NAN-2551: arrivals held back while the analyst is reading
                    further down. NAN-3254: the tail never pauses on volume
                    (it is a rolling window), so this is only ever "N new". */}
                {tailActive && tailState.buffered.length > 0 && (
                  <button
                    type="button"
                    onClick={showBufferedTailRows}
                    className="mb-1.5 inline-flex items-center gap-1.5 px-2.5 py-1 text-[11px] rounded-md border border-emerald-600/50 bg-emerald-600/10 text-emerald-800 hover:bg-emerald-600/15 dark:border-emerald-500/35 dark:bg-emerald-500/10 dark:text-emerald-400 transition-colors"
                  >
                    <span className="w-[5px] h-[5px] rounded-full bg-emerald-600 dark:bg-emerald-400" />
                    <span className="font-mono tabular-nums">{tailState.buffered.length.toLocaleString()}</span>
                    <span>new events</span>
                    <span className="text-emerald-700/70 dark:text-emerald-400/60">· show</span>
                  </button>
                )}
                <div className="w-full min-w-0 overflow-x-hidden md:[overflow-x:clip]">
                  <SearchFooterProvider value={reportPhase2}>
                  <LiveRunProvider value={liveRun}>
                  {/* NAN-2551/NAN-2557: the query's own total stays frozen — a
                      tail tick never pays for a count companion — but the set on
                      screen really did grow by the arrivals, and the
                      infinite-scroll bound compares `totalCount` against
                      `results.length`. `displayTotalCount` is that same sum, and
                      it is what every other total on the page renders. */}
                  <SearchResults
                    completeness={completeness}
                    results={displayResults}
                    totalCount={displayTotalCount}
                    totalCountExact={totalCountExact}
                    prependedRowCount={tailState.rows.length}
                    isSearching={isSearching}
                    hasSearched={hasSearched}
                    isAggregateQuery={isAggregateQuery}
                    displayType={displayType}
                    histogramHasData={histogramData?.some((b) => b.count > 0) ?? false}
                    query={query}
                    executedQuery={executedQuery}
                    onAddToQuery={addToQuery}
                    onSetQuery={(newQuery) => {
                      setQuery(newQuery);
                      handleSearch(1, false, newQuery, queryMode, timeRange);
                    }}
                    onSetQueryWithTime={(q, startIso, endIso) => {
                      const tr = { type: 'custom' as const, start: new Date(startIso), end: new Date(endIso) };
                      setQuery(q);
                      setTimeRange(tr);
                      handleSearch(1, false, q, queryMode, tr);
                    }}
                    pagingComplete={pagingComplete || !!(durableResultCursor && durableResultCursor.loadedPage + 1 >= durableResultCursor.pages)}
                    onLoadMore={loadMore}
                    onVisibleRowsChange={handleVisibleRowsChange}
                    onDrilldown={handleDrilldown}
                    currentPage={tablePage}
                    pageSize={tablePageSize}
                    resultRowOffset={durableResultCursor?.rowOffset ?? 0}
                    onPageChange={handleTablePageChange}
                    onPageSizeChange={handleTablePageSizeChange}
                    notebookActive={notebookActive}
                    onAddToNotebook={addEntityToNotebook}
                    onAddAllEntitiesToNotebook={addEntitiesToNotebook}
                    onFetchLog={fetchLog}
                    columnOrder={columnOrder}
                    assetPrevalenceFilter={assetPrevalenceFilter}
                    timeRange={apiTimeRange}
                    melodEnabled={melodStatus?.connected || false}
                    onSummarize={() => setAnalyzeActive(true)}
                    asyncJobId={asyncJobId}
                    asyncJobStatus={asyncJobStatus}
                    asyncJobProgress={asyncJobProgress}
                    queuePosition={queuePosition}
                    estimatedWait={estimatedWait}
                    onCancelAsyncJob={handleCancelAsyncJob}
                    onOpenJobs={() => setJobsModalOpen(true)}
                    isStreamingResults={isStreamingResults}
                    cachedAt={cachedResultsTimestamp}
                    onRefreshCache={() => { setCachedResultsTimestamp(null); handleSearch(1, false, undefined, undefined, undefined, false); }}
                    fieldsCollapsed={showFieldsPanel && !fieldsPanelExpanded}
                    fieldsCount={fieldStats.length}
                    onExpandFields={() => { userToggledFieldsPanel.current = true; setFieldsPanelExpanded(true); }}
                  />
                  </LiveRunProvider>
                  </SearchFooterProvider>
                </div>
              </div>
            </div>
          );
        })()}
      </div>

      {/* Mobile Fields drawer */}
      <Sheet open={mobileFieldsOpen} onOpenChange={setMobileFieldsOpen}>
        <SheetContent side="left" className="w-80 bg-sidebar p-0">
          <SheetTitle className="sr-only">Field Index</SheetTitle>
          <FieldsPanel
            fieldStats={fieldStats}
            baseFieldStats={baseFieldStats}
            isAggregateQuery={isAggregateQuery}
            showBaseFields={showBaseFields}
            onToggleShowBaseFields={() => setShowBaseFields(!showBaseFields)}
            expandedFields={expandedFields}
            onToggleField={toggleField}
            onAddToQuery={(field, value, exclude) => { addToQuery(field, value, exclude); setMobileFieldsOpen(false); }}
            onGroupBy={(field) => { groupByField(field); setMobileFieldsOpen(false); }}
            isExpanded={true}
            onToggleExpanded={() => setMobileFieldsOpen(false)}
            isLoading={fieldStatsLoading && fieldStats.length === 0}
            isLoadingMore={fieldStatsLoading && fieldStats.length > 0}
            isReducedFieldSet={fieldStatsReduced}
            onLoadAllFields={loadAllFieldStats}
            // NAN-3299: scope to the executed search, not the editor text —
            // a keystroke must not refetch the panel's ext names / values.
            query={executedQuery || query}
            timeRange={apiTimeRange}
            onFetchFieldValues={(field, q, start, end) =>
              // NAN-1559: use the executed-search dataset (snapshotted at search
              // time), not the live selector — see the panel above.
              fetchSearchFieldValues({ field, query: q, start, end, limit: 100, dataset: lastFieldStatsRequestRef.current?.dataset ?? dataset })
            }
          />
        </SheetContent>
      </Sheet>

      {/* Add to Dashboard Dialog — /api/dashboards is tenant-scoped on shared */}
      <AddToDashboardDialog
        open={showAddToDashboardDialog}
        onOpenChange={setShowAddToDashboardDialog}
        query={query}
        queryMode={queryMode}
        timeRange={timeRange}
      />

      {/* Search stats bar */}
      <SearchStatsBar
        isSearching={footerIsSearching}
        hasSearched={hasSearched}
        totalCount={footerTotalCount}
        totalCountExact={footerGated ? true : totalCountExact}
        executionTimeMs={footerExecutionTimeMs}
        firstRowsMs={footerGated ? undefined : splitTiming?.firstRowsMs}
        completionMs={footerGated ? undefined : splitTiming?.completionMs}
        asyncJobProgress={asyncJobProgress}
        asyncJobStatus={asyncJobStatus}
        backgroundJob={!!asyncJobId}
        queuePosition={queuePosition}
        isStreamingResults={isStreamingResults}
        onCancel={handleCancelAsyncJob}
        tailActive={tailActive}
        tailInterval={tailInterval}
        timeWindow={runTimeWindowLabel}
      />
    </div>
  );
}
