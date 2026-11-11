// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState, useMemo, useRef, useCallback, useEffect } from 'react';
import { SearchFooterProvider, PHASE2_REPORTING_MODES, type Phase2Status } from '@/components/search/footer-reporter';
import { LiveRunProvider } from '@/components/search/live-run-context';
import { useQueryClient, useQuery } from '@tanstack/react-query';
import { Link as RouterLink, useLocation, useNavigate } from 'react-router-dom';
// #7041: hunt queries live in the URL fragment, never the request URL.
import { useSearchFragmentParams } from '@/hooks/use-search-fragment-params';
import { searchQueryForUrl } from '@/lib/search-query-url';
import { useUserPreferences } from '@/contexts/UserPreferencesContext';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuShortcut, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';
import { DateTimeRangePicker } from '@/components/ui/date-time-range-picker';
import { formatTimelineLabel, parseUTCTimestamp } from '@/lib/date-utils';
import { cn, injectBeforeFirstPipe, isClickHouseDefault, stripComments } from '@/lib/utils';
import { searchTimingBreakdown, type SearchTimingBreakdown } from '@/lib/search-timing';
import { safeRandomUUID } from '@/lib/uuid';
import { consumeSearchAutoRun, isOutsideArrival, isSearchAutoRunGranted, rememberTabSearch, tabAlreadyRan } from '@/lib/search-auto-run';
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
  useGroups,
  useCreateSharedSearch,
  useGetSharedSearch,
  useMelodStatus,
  useStoreQueryExplanation,
  useGetQueryExplanation,
  toApiTimeRange,
  type TimeRangeValue
} from '@/hooks/use-api';
import { api } from '@/lib/api';
import type { ApiError, ParseErrorDetails, MelodApiResponse } from '@/lib/api';
import { useMelodJob } from '@/enterprise/hooks/use-melod-job';
import { useAuth } from '@/contexts/AuthContext';
import { useSearchHistory } from '@/hooks/useSearchHistory';
import { resolveRunTimeRange, urlTimeRange, type SearchRunScope } from './search-run-scope';
import { formatTimeWindowLabel, readTimeRangeParams, writeTimeRangeParams } from '@/lib/time-range';
import { parseTimestampAsUTC } from '@/lib/parse-timestamp-utc';
import { useScrollContainer } from '@/contexts/ScrollContainerContext';
import { buildSearchTimeline } from './search-timeline';
import {
  applyTailBatch,
  collectTailPages,
  emptyTailState,
  flushTailBuffer,
  rememberTailKeys,
  selectTailRows,
  tailArmRows,
  tailCountedArrivals,
  tailFollowsRange,
  tailPrependEligible,
  tailSupervisor,
  tailSupervisorTick,
  tailWatermark,
  tailWindow,
  TAIL_FETCH_LIMIT,
  TAIL_STALE_GUARD_MS,
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
import { useIsMobile } from '@/hooks/use-mobile';
import { useSchemaFieldMap } from '@/hooks/useSchemaFieldMap';
import { Sheet, SheetContent, SheetTitle } from '@/components/ui/sheet';
import { useNotebookCapture } from '@/enterprise/contexts/NotebookContext';
import { TimelineVisualization, FieldsPanel, FIELD_STATS_PINNED_COLUMNS, SearchResults, SearchQueryInput, SavedQueriesPalette, SearchJobsModal, PrevalenceSlider, DatasetSelector, type FieldStat } from '@/components/search';
import { registerSearchAnalysisSource, startSearchAnalysis, MAX_ANALYZE_ROWS, NO_SEARCH_TO_ANALYZE, type SearchAnalysisContext } from '@/enterprise/components/pivt/drafts/search-analysis';
import { openPivtPanel } from '@/enterprise/components/pivt/commands/router';
import { useCapabilities } from '@/hooks/use-capabilities';
import { ScheduleReportDialog, type ScheduleReportPreset } from '@/components/reports/ScheduleReportDialog';
import { useHereCardOverride } from '@/contexts/PageContext';
import { isPageInStoredRange, jobFailureCode, jobPollPolicy, nextContinuationPage, pageableRowCount } from '@/lib/search-job';
import type { SearchJobSummary } from '@/lib/api';
import { registerDynamicFields } from '@/components/editor';
import { spillFieldName } from '@/components/search/field-buckets';
import { SearchDemoHint } from '@/components/DemoHints';
import { SearchStatsBar } from '@/components/search/SearchStatsBar';
import { AddToDashboardDialog } from '@/components/dashboard';
import { nplQuotedBody } from '@/lib/npl-quote';
// NAN-2209: shared with SearchResults so both group-by entry points and the
// query-rewrite paths split the pipeline identically (regex-aware).
import { getBaseSearch, getPipeCommands, buildGroupByQuery } from '@/lib/npl-pipeline';
import { Checkbox } from '@/components/ui/checkbox';
import { resultRowKeyFields, resultRowSource } from '@/lib/result-row-source';

interface SearchResult {
  id: string;
  timestamp: Date;
  source: string;
  fields: Record<string, unknown>;
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
  serverFieldStats: Array<{ name: string; count: number; top_values: [string, number][]; cardinality?: number }> | null;
  // Whether serverFieldStats were computed over a reduced column set (so restore
  // can re-offer "Show all fields" / NAN-1503 auto-fetch). Null until stats land.
  fieldStatsReduced: boolean | null;
  totalCount: number;
  executionTimeMs: number | null;
  timing?: SearchTimingBreakdown | null;
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
  const timeKey = timeRange.type === 'custom' && timeRange.start && timeRange.end
    ? `${timeRange.start.toISOString()}_${timeRange.end.toISOString()}`
    : timeRange.preset;
  return `${mode}:${dataset}:${query}:${timeKey}`;
}

// Helper function to flatten nested objects (like metadata) into underscore-notation fields
// This matches the flattenFields function in SearchResults.tsx
const flattenFieldsForStats = (fields: Record<string, unknown>, prefix = ''): [string, unknown][] => {
  const result: [string, unknown][] = [];
  
  for (const [key, value] of Object.entries(fields)) {
    const fullKey = prefix ? `${prefix}_${key}` : key;
    
    // Skip ClickHouse default values (null, undefined, empty string, 0 for most fields)
    if (isClickHouseDefault(value, key)) continue;
    
    // If it's the metadata field, flatten its contents
    if (key === 'metadata') {
      let metadataObj: Record<string, unknown> | null = null;
      
      if (typeof value === 'object' && !Array.isArray(value) && value !== null) {
        metadataObj = value as Record<string, unknown>;
      } else if (typeof value === 'string' && value.startsWith('{')) {
        try {
          const parsed = JSON.parse(value);
          if (typeof parsed === 'object' && !Array.isArray(parsed)) {
            metadataObj = parsed;
          }
        } catch {
          // Not valid JSON, treat as regular string
        }
      }
      
      if (metadataObj) {
        const nested = flattenFieldsForStats(metadataObj, 'metadata');
        result.push(...nested);
      } else if (value) {
        result.push([fullKey, value]);
      }
    } else if (typeof value === 'object' && !Array.isArray(value) && prefix === '') {
      // For other top-level objects, keep them as-is
      result.push([fullKey, value]);
    } else {
      result.push([fullKey, value]);
    }
  }
  
  return result;
};

// NAN-1427: derive the column set the field index needs from the rows the
// analyst can actually see, plus the pinned "Selected" columns. The server's
// field-stats query reads every requested column over all matching rows, so
// the default request covers visible + pinned columns only (measured 50x less
// I/O than the full ~90-column inventory); the panel's "Index all fields"
// action refetches without `columns` for the full inventory. Unknown names
// (ext-JSON keys etc.) are dropped server-side by intersection with the live
// table inventory.
// NAN-1507 follow-up: when a search matches fewer than this many rows, the full
// field-stats scan is ~free (rows-scanned dominates cost, and it's row-bounded to
// 100k server-side — NAN-1506), so fetch the FULL column inventory straight away
// instead of the reduced set + "Show all fields" teaser. Targeted hunts (the
// common case) then get the complete field list with no extra click; broad
// searches keep the reduced fetch. Gated on the RELIABLE backend count only — an
// absent/0 count falls through to the reduced (safe) path, never the full scan.
const AUTO_SHOW_ALL_RESULT_THRESHOLD = 1000;

const collectFieldStatsColumns = (results: SearchResult[]): string[] => {
  const cols = new Set<string>(FIELD_STATS_PINNED_COLUMNS);
  // First 200 rows are plenty to discover the visible column population.
  for (const result of results.slice(0, 200)) {
    if (result?.fields && typeof result.fields === 'object' && result.fields !== null) {
      for (const key of Object.keys(result.fields)) cols.add(key);
    }
  }
  return Array.from(cols);
};

/**
 * Event time of a result row (OCSF `time`, UDM `timestamp`). An event with no
 * time is an INVALID date, never "now": the live tail's watermark and the
 * histogram must not treat a timeless row as a fresh arrival.
 */
function tailRowTimestamp(row: Record<string, unknown>): Date {
  const value = row.time ?? row.timestamp;
  if (value instanceof Date) return value;
  if (typeof value === 'number' && Number.isFinite(value)) return new Date(value);
  return parseTimestampAsUTC(typeof value === 'string' ? value : '');
}

function tailRowSource(row: Record<string, unknown>): string {
  return resultRowSource(row);
}

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
  const [searchParams, setSearchParams] = useSearchFragmentParams();
  // The router's current params for async callbacks (NAN-3263's re-anchor
  // writes the rolling window into the URL after an await).
  const searchParamsRef = useRef(searchParams);
  searchParamsRef.current = searchParams;
  const queryClient = useQueryClient();
  const { defaultTimeRange, queryMode: userQueryMode } = useUserPreferences();

  useDocumentTitle('Search');

  // Parse URL params
  const urlQuery = searchParams.get('q') || '';
  const urlMode = (searchParams.get('mode') as 'piped' | 'sql' | 'natural') || 'piped';
  const urlShortId = searchParams.get('s') || '';
  // NAN-5235: `run` only auto-runs with a live in-app grant for this exact
  // query (see lib/search-auto-run). Anything else loads the query and asks.
  const urlRunToken = searchParams.get('run');
  const urlAutoRun = useMemo(
    () => isSearchAutoRunGranted(urlRunToken, urlQuery),
    [urlRunToken, urlQuery],
  );
  const urlRunUngranted = !!urlRunToken && !!urlQuery && !urlAutoRun;
  // NAN-5235: the first history entry of this document (key "default") is an
  // arrival from outside the app: a link, a bookmark, a typed URL. In-app
  // navigations carry their own key, which survives a reload in
  // history.state and which another site cannot set. The return to the
  // original URL after sign-in is marked as an outside arrival too. Read once.
  const routerLocation = useLocation();
  const routerLocationRef = useRef(routerLocation);
  routerLocationRef.current = routerLocation;
  const arrivedFromOutsideRef = useRef(isOutsideArrival(routerLocation));
  const mayRunUrlQueryOnArrival = (q: string) => !arrivedFromOutsideRef.current || tabAlreadyRan(q);
  // The same rule for a URL change after mount (back/forward, or a fragment
  // navigation another window performed): only an entry this app created in
  // its own history may run its query; anything else loads and asks.
  const mayRunUrlQueryAt = (location: { key: string; state: unknown }, q: string) =>
    !isOutsideArrival(location) || tabAlreadyRan(q);
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
  const [queryMode, setQueryMode] = useState<'piped' | 'sql'>(urlMode === 'natural' ? 'piped' : urlMode as 'piped' | 'sql');
  // NAN-1534: observability dataset the nPL pipeline runs against. "logs" (the
  // UDM lane) is the default; "spans"/"metrics" target the OTLP tables. The
  // dedicated /observability explorers are the primary span/metric surfaces —
  // this toggle lets analysts run ad-hoc nPL against those tables in-place.
  // "risk" (NAN-1805) targets the derived accumulated-entity-risk grain.
  const [dataset, setDataset] = useState<import('@/lib/api/types').SearchDataset>(() => {
    const d = searchParams.get('dataset');
    return d === 'spans' || d === 'metrics' || d === 'risk' ? d : 'logs';
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
  // NAN-5235: a linked query is loaded but waits for an explicit Run.
  const [linkedRunPending, setLinkedRunPending] = useState(false);
  const [isAggregateQuery, setIsAggregateQuery] = useState(false);
  const [displayType, setDisplayType] = useState<import('@/lib/api/types').DisplayType | undefined>(undefined);
  const [columnOrder, setColumnOrder] = useState<string[] | undefined>(undefined);


  // Async search job state
  const [asyncJobId, setAsyncJobId] = useState<string | null>(null);
  const [asyncJobStatus, setAsyncJobStatus] = useState<import('@/lib/api/types').SearchJobStatusValue | null>(null);
  const [asyncJobProgress, setAsyncJobProgress] = useState<import('@/lib/api/types').SearchJobProgress | null>(null);
  // NAN-4915: durable background-job detail (attempt / origin / stored rows)
  // for the job currently attached to this page.
  const [asyncJobInfo, setAsyncJobInfo] = useState<import('@/lib/api/types').DurableJobInfo | null>(null);
  // NAN-4915: continuation state of a COMPLETED durable job whose rows are on
  // screen. While set, "load more" and table paging read the job's stored rows
  // instead of re-running the search.
  const jobContinuationRef = useRef<{ jobId: string; rowCount: number } | null>(null);
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
  // header says why the tail went quiet instead of it just vanishing.
  const [tailStoppedForRange, setTailStoppedForRange] = useState(false);
  useEffect(() => { if (tailActive) setTailStoppedForRange(false); }, [tailActive]);
  const tailTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  // NAN-3244: the tick supervisor (see search-tail.ts). This build has no
  // server follow stream (that was the lake's part-log follow), so every tick
  // polls; the supervisor only guarantees no stuck flag can stop the tail.
  const tailSupervisorRef = useRef(tailSupervisor());
  // When the page's own search started (0 = idle). Blocks tail ticks for at
  // most TAIL_STALE_GUARD_MS, so a stuck flag cannot kill the tail.
  const tailSearchingSinceRef = useRef(0);
  // Bumped whenever a real search resets the tail; late tail responses from
  // before the reset are dropped (NAN-2557).
  const tailEpochRef = useRef(0);
  // NAN-2551: tail arrivals live in their own list rendered in front of
  // `searchResults`, so pagination offsets and every `searchResults.length`
  // sum stay exactly as the paged search left them.
  const [tailState, setTailState] = useState<TailState<SearchResult>>(() => emptyTailState<SearchResult>());
  const tailStateRef = useRef(tailState);
  useEffect(() => { tailStateRef.current = tailState; }, [tailState]);
  // Keys of everything on screen, so the deliberate window overlap cannot
  // re-prepend a row the analyst already has.
  const tailSeenKeysRef = useRef<Set<string>>(new Set());
  // Newest event time seen, clamped to now (see search-tail.ts).
  const tailWatermarkRef = useRef(0);
  // When the current search run started (epoch ms, browser clock). Rows
  // ingested at or before it were in its result set; the tail's arming read
  // seeds their keys so they are never re-counted as arrivals (see
  // runTailRefresh). Clock skew between browser and ClickHouse moves the
  // boundary by the skew only.
  const tailSearchRanAtRef = useRef(0);
  // When the in-flight tail poll started (0 = none).
  const tailPollStartedAtRef = useRef(0);
  // Whether the analyst is at the top of the list. Arrivals are held back
  // while they read further down, so the viewport never jumps under them.
  const tailAtTopRef = useRef(true);
  const runTailRefreshRef = useRef<() => void>(() => {});
  // NAN-3254: arrivals newer than this cutoff are counted into the histogram;
  // anything at or before it was in the histogram the search returned.
  const tailHistogramCutoffRef = useRef(0);
  // Where the chart's window ends while tailing (epoch ms); null = the picker's.
  const [tailChartEndMs, setTailChartEndMs] = useState<number | null>(null);
  const advanceTailTimelineRef = useRef<(arrivalTimesMs: number[]) => void>(() => {});
  // NAN-3263: the live count is re-anchored on a server read of the rolling
  // window (see search-tail-histogram.ts).
  const tailArrivalLogRef = useRef<number[]>([]);
  const tailReanchorRef = useRef<{ lastRequestedMs: number; controller: AbortController | null }>({
    lastRequestedMs: 0,
    controller: null,
  });
  const reanchorTailTimelineRef = useRef<(tailIntervalMs: number) => void>(() => {});
  const resultsScrollContainer = useScrollContainer();
  const resultsAreaRef = useRef<HTMLDivElement | null>(null);

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

  // Pagination state for tabular views (stats, table)
  const [tablePage, setTablePage] = useState(0);
  const [tablePageSize, setTablePageSize] = useState(50);

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
  const { user, hasPermission, isAuthenticated } = useAuth();

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
  const schemaFields = useSchemaFieldMap();
  const [mobileFieldsOpen, setMobileFieldsOpen] = useState(false);
  
  const { capabilities } = useCapabilities();

  // Pagination state
  const [currentPage, setCurrentPage] = useState(1);
  const [totalCount, setTotalCount] = useState(0);
  /**
   * The total every surface on the page renders (NAN-2551 / NAN-2557).
   * The query's own total is frozen while tailing (a tick never pays for a
   * count companion), but the set on screen really did grow by the arrivals.
   * Buffered arrivals are excluded: they are counted by their own "N new"
   * chip. NAN-3254: the tail list is a rolling window, so this uses every
   * arrival shown (`arrived`), not the capped `rows.length`.
   */
  const displayTotalCount = totalCount + tailCountedArrivals(tailState);
  // Peak `rows_scanned` from streaming `onProgress` SSE events. Tracked so
  // the >1M-row warning can fire on aggregate queries, whose `total_count`
  // is the post-aggregation output size (e.g. 20 rows from `head 20`) and
  // never crosses the 1M threshold on its own.
  const [peakRowsScanned, setPeakRowsScanned] = useState(0);
  const [limitWarningDismissed, setLimitWarningDismissed] = useState(false);
  const [pageSize] = useState(50);

  // PIVT "Here" card override — reflects live search state so the
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
              ? ['Summarize these results', 'Pivot by source IP', 'Create a detection from this query']
              : ['Widen the time range', 'Remove a filter', 'Summarize zero-result patterns'],
        }
      : null
  );

  // Query execution time
  const [executionTimeMs, setExecutionTimeMs] = useState<number | null>(null);
  const [searchTiming, setSearchTiming] = useState<SearchTimingBreakdown | null>(null);

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
  const requestQueryCorrection = useCallback((errorCode: string, errorMsg: string, failedQuery: string, fieldSuggestions?: string[]) => {
    // Only attempt correction for correctable error types
    const correctableCodes = ['PARSE_ERROR', 'FIELD_NOT_FOUND', 'DATABASE_ERROR', 'QUERY_ERROR', 'INTERNAL_ERROR', 'JOB_FAILED'];
    if (!correctableCodes.includes(errorCode)) return;
    // Don't correct empty queries or permission errors
    if (!failedQuery?.trim()) return;

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
    }).catch((err) => {
      console.error('[QueryCorrection] Failed:', err);
    }).finally(() => {
      setIsCorrectingQuery(false);
    });
  }, []);

  // Request AI best practices review after a successful complex query
  const requestQueryReview = useCallback((successfulQuery: string) => {
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
  }, [queryMode]);

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
  const { data: _groups } = useGroups();
  const { mutate: createSharedSearch } = useCreateSharedSearch();
  const { mutate: getSharedSearch } = useGetSharedSearch();
  const buildQueryJob = useMelodJob<MelodApiResponse>();
  const aiLoading = buildQueryJob.loading;
  const { data: melodStatus } = useMelodStatus();
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
  } = useSearchHistory();

  // Notebook capture for auto-documenting investigations
  const { captureSearch, isActive: notebookActive, addEntityToNotebook, addEntitiesToNotebook } = useNotebookCapture();

  const canSave = hasPermission('search:save');
  const canShare = hasPermission('search:share');
  const canSql = hasPermission('search:sql');

  useEffect(() => {
    // Keep the empty search console aligned with the user's preferred mode.
    // Once the user has query text, preserve the live mode and let query parsing drive it.
    if (query.trim()) return;
    setQueryMode(userQueryMode === 'advanced' && canSql ? 'sql' : 'piped');
  }, [query, userQueryMode, canSql]);

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
    // The timeline's Rarity tab is page URL state too (NAN-4927): a run keeps it.
    if (searchParamsRef.current.get('view') === 'rarity') params.set('view', 'rarity');
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

  /**
   * The timeline's `view=rarity` flag (NAN-4927). Search owns the fragment, so
   * it owns this flag too; the timeline only asks for it to change. Our own
   * write, never navigation (prevUrlRef), and it never pushes history.
   */
  const setUrlRarityView = useCallback((rarity: boolean) => {
    const params = new URLSearchParams(searchParamsRef.current);
    if ((params.get('view') === 'rarity') === rarity) return;
    if (rarity) params.set('view', 'rarity');
    else params.delete('view');
    prevUrlRef.current = params.toString();
    setSearchParams(params, { replace: true });
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
    return params.toString() ? `${baseUrl}#${params.toString()}` : baseUrl;
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
      const shortUrl = `${window.location.origin}${window.location.pathname}#s=${result.id}`;
      await navigator.clipboard.writeText(shortUrl);
      setCopiedUrl(true);
      setTimeout(() => setCopiedUrl(false), 2000);
    } catch (err) {
      setSearchError(handleError(err, 'Failed to create short URL'));
    } finally {
      setIsCreatingShortUrl(false);
    }
  }, [query, queryMode, timeRange, createSharedSearch]);

  // Clear async job state
  const clearAsyncJob = useCallback(() => {
    if (asyncJobPollingRef.current) {
      clearInterval(asyncJobPollingRef.current);
      asyncJobPollingRef.current = null;
    }
    setAsyncJobId(null);
    setAsyncJobStatus(null);
    setAsyncJobProgress(null);
    setAsyncJobInfo(null);
    setQueuePosition(null);
    setEstimatedWait(null);
  }, []);

  // Cancel async job
  const handleCancelAsyncJob = useCallback(() => {
    if (asyncJobId) {
      api.cancelSearchJob(asyncJobId).catch(() => {});
      clearAsyncJob();
      setIsSearching(false);
    }
  }, [asyncJobId, clearAsyncJob]);

  // Cleanup polling, SSE, and tail on unmount
  useEffect(() => {
    return () => {
      if (asyncJobPollingRef.current) {
        clearInterval(asyncJobPollingRef.current);
      }
      if (sseControllerRef.current) {
        sseControllerRef.current.abort();
      }
      if (tailTimerRef.current) {
        clearInterval(tailTimerRef.current);
      }
      tailReanchorRef.current.controller?.abort();
    };
  }, []);

  // Keep ref in sync with isSearching so the tail timer callback reads fresh value
  useEffect(() => {
    tailSearchingSinceRef.current = isSearching ? (tailSearchingSinceRef.current || Date.now()) : 0;
    // NAN-3273: a run that ended (failed, cancelled) without installing a
    // timeline must not keep showing the held one.
    if (!isSearching) setTimelineHold(null);
  }, [isSearching]);

  // NAN-2551: whether the analyst is at the top of the results list. Read on
  // the page's scroll container, so arrivals prepend while the first rows are
  // in view and are held behind an "N new" chip once the reader scrolls on.
  useEffect(() => {
    const container = resultsScrollContainer?.current;
    if (!container) return;
    const update = () => {
      const area = resultsAreaRef.current;
      if (!area) { tailAtTopRef.current = true; return; }
      // At the top while the start of the list (plus about one row) is still
      // inside the container's viewport.
      const offset = area.getBoundingClientRect().top - container.getBoundingClientRect().top;
      tailAtTopRef.current = offset >= -60;
    };
    update();
    container.addEventListener('scroll', update, { passive: true });
    return () => container.removeEventListener('scroll', update);
  }, [resultsScrollContainer]);

  // Live tail (NAN-2551 / NAN-3244 / NAN-3254 / NAN-3263): one supervisor tick
  // per interval polls for arrivals, slides the timeline with the clock and
  // periodically re-reads the rolling window's count from the server.
  useEffect(() => {
    if (tailTimerRef.current) {
      clearInterval(tailTimerRef.current);
      tailTimerRef.current = null;
    }

    if (!tailActive || !query?.trim()) return;

    // NAN-2551: re-arm against whatever is on screen right now, then let each
    // tick prepend arrivals. The tick body lives behind a ref so the timer is
    // never torn down mid-run.
    tailWatermarkRef.current = 0;
    // The histogram covers the whole executed query window, including events
    // newer than the displayed page; counting from the newest row would double
    // count those when the tail's overlap delivers them (NAN-3741).
    const histogramEndMs = new Date(resolveRunTimeRange(runScopeRef.current, timeRange).end).getTime();
    tailHistogramCutoffRef.current = tailHistogramCutoff(tailHistogramCutoffRef.current, histogramEndMs);
    const prependEligible = tailPrependEligible(queryMode, isAggregateQuery, displayType);
    // NAN-3263: the first tick re-anchors the count on the rolling window.
    tailReanchorRef.current.lastRequestedMs = 0;
    tailSupervisorRef.current = tailSupervisor();

    const tick = () => {
      const action = tailSupervisorTick(tailSupervisorRef.current, {
        nowMs: Date.now(),
        followEligible: false,
        intervalMs: tailInterval,
        pollStartedAtMs: tailPollStartedAtRef.current,
        searchingSinceMs: tailSearchingSinceRef.current,
      });
      if (action.poll) runTailRefreshRef.current();
      // NAN-3254: slide the chart with the clock even on a quiet source.
      if (prependEligible) advanceTailTimelineRef.current([]);
      // NAN-3263: and periodically re-read the true rolling window's count.
      if (prependEligible) reanchorTailTimelineRef.current(tailInterval);
    };
    tailTimerRef.current = setInterval(tick, tailInterval);

    return () => {
      if (tailTimerRef.current) {
        clearInterval(tailTimerRef.current);
        tailTimerRef.current = null;
      }
      tailSupervisorRef.current = tailSupervisor();
      tailReanchorRef.current.controller?.abort();
      tailReanchorRef.current.controller = null;
    };
  }, [tailActive, tailInterval, queryMode, isAggregateQuery, displayType, dataset,
      query, executedQuery, timeRange, prevalenceMax]); // eslint-disable-line react-hooks/exhaustive-deps

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
    jobDataset?: import('@/lib/api/types').SearchDataset
  ) => {
    const effectiveDataset = jobDataset ?? dataset;
    const results: SearchResult[] = (response.results || [])
      .filter((r: unknown) => r != null && typeof r === 'object')
      .map((r: Record<string, unknown>, i: number) => ({
        id: `result-${i}`,
        timestamp: parseUTCTimestamp(r?.timestamp as string),
        source: resultRowSource(r),
        fields: (r && typeof r === 'object') ? r : {},
      }));

    setSearchResults(results);
    setExecutedQuery(currentQuery);
    setTotalCount(response.total_count || results.length);
    if (response.generated_sql) setGeneratedSql(response.generated_sql);
    const timing = searchTimingBreakdown(response);
    setExecutionTimeMs(timing.displayTimeMs);
    setSearchTiming(timing);
    if (response.display_type) {
      setDisplayType(response.display_type);
      setTablePage(0);
    }
    if (response.column_order) setColumnOrder(response.column_order);
    const histData = response.histogram && response.histogram.length > 0
      ? response.histogram.map(bucket => ({ time: bucket.time, count: bucket.count }))
      : [];
    // Always update histogram (even if empty) to clear stale data from previous searches
    setHistogramData(histData);

    // Cache async results for back-navigation
    const cacheKey = buildCacheKey(currentQuery, currentTimeRange, currentMode, effectiveDataset);
    const cacheEntry: CachedSearchResult = {
      results,
      histogramData: histData,
      serverFieldStats: null,
      fieldStatsReduced: null,
      totalCount: response.total_count || results.length,
      executionTimeMs: timing.displayTimeMs,
      timing,
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

    // Handle query warnings
    if (response.warnings && response.warnings.length > 0) {
      const errorWarning = response.warnings.find(w => w.severity === 'error');
      const warningWarning = response.warnings.find(w => w.severity === 'warning');
      const mainWarning = errorWarning || warningWarning || response.warnings[0];

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
      // Small, specific result set → fetch the FULL inventory directly (no
      // reduced set / teaser); broad → reduced. Only on a real backend count.
      const fsSmall = (response.total_count ?? 0) > 0 && (response.total_count ?? 0) < AUTO_SHOW_ALL_RESULT_THRESHOLD;
      fetchFieldStats({ ...fsRequest, columns: fsSmall ? undefined : collectFieldStatsColumns(results), signal: runControllerRef.current?.signal })
        .then(fieldStatsResponse => {
          if (fieldStatsResponse.fields && fieldStatsResponse.fields.length > 0) {
            setServerFieldStats(fieldStatsResponse.fields);
            setFieldStatsReduced(!fsSmall);
            // Update cache entry with field stats
            const cached = searchResultCache.get(cacheKey);
            if (cached) {
              cached.serverFieldStats = fieldStatsResponse.fields;
              cached.fieldStatsReduced = !fsSmall;
            }
          }
        })
        .catch(err => {
          console.warn('Failed to fetch field stats:', err);
        });
    }

    // Capture search in notebook (if active)
    const apiTime = resolveRunTimeRange(runScopeRef.current, currentTimeRange);
    captureSearch(
      currentQuery,
      currentMode,
      response.total_count || results.length,
      response.execution_time_ms,
      apiTime.start,
      apiTime.end
    );

    // Update AI conversation history with result summary
    const resultCount = response.total_count || results.length;
    if (resultCount > 0) {
      setAiConversationHistory(prev => {
        if (prev.length === 0) return prev;
        const updated = [...prev];
        const lastIdx = updated.length - 1;
        const keyFields = results.slice(0, 3).map(r => {
          // NAN-5271: the row's own fields (OCSF paths on an OCSF row).
          return resultRowKeyFields(r.fields as Record<string, unknown>);
        }).filter(Boolean).join(' | ');

        updated[lastIdx] = {
          ...updated[lastIdx],
          result_summary: `Found ${resultCount.toLocaleString()} events`,
          key_context: keyFields || undefined,
        };
        return updated;
      });
    }
  }, [fetchFieldStats, captureSearch, toApiTimeRange, requestQueryReview, dataset]);

  // Start polling for async job results
  const startAsyncJobPolling = useCallback((
    jobId: string,
    currentQuery: string,
    currentTimeRange: TimeRangeValue,
    currentMode: 'piped' | 'sql',
    isAggregate: boolean,
    // NAN-1825: dataset the job's search targeted — forwarded to
    // processAsyncJobResult so results cache under the right dataset.
    jobDataset?: import('@/lib/api/types').SearchDataset
  ) => {
    // Clear any existing polling interval to prevent leaks
    if (asyncJobPollingRef.current) {
      clearInterval(asyncJobPollingRef.current);
      asyncJobPollingRef.current = null;
    }

    // NAN-4915: durable background jobs (`sjob_…`) survive restarts and are
    // bounded server-side by the job time limit, so the page keeps attaching
    // instead of giving up after 5 minutes. Legacy jobs keep the old cutoff.
    const { intervalMs: pollInterval, maxPolls } = jobPollPolicy(jobId);
    let pollCount = 0;

    asyncJobPollingRef.current = setInterval(async () => {
      // Guard: if polling was cleared, don't continue
      if (!asyncJobPollingRef.current) return;

      try {
        pollCount++;
        if (pollCount > maxPolls) {
          clearAsyncJob();
          setIsSearching(false);
          setSearchError({ code: 'TIMEOUT', message: 'Search job timed out after 5 minutes' });
          return;
        }

        const status = await api.getSearchJob(jobId);

        // Guard again after async call - polling might have been cleared while waiting
        if (!asyncJobPollingRef.current) return;

        setAsyncJobStatus(status.status);
        setAsyncJobProgress(status.progress || null);
        setAsyncJobInfo(status.durable ?? null);

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
          processAsyncJobResult(status.result, currentQuery, currentTimeRange, currentMode, isAggregate, jobDataset);
          if (status.durable) {
            const rowCount = status.durable.row_count ?? status.result.results.length;
            jobContinuationRef.current = { jobId, rowCount };
            if (status.durable.result_truncated) {
              // Codex P2-7: page only over the stored rows; the larger match
              // count is reported separately in the notice.
              setTotalCount(pageableRowCount(status.result.total_count, rowCount, true));
              setSearchError({
                code: 'JOB_RESULT_TRUNCATED',
                message: `${status.result.total_count.toLocaleString()} rows matched; this background search kept the first ${rowCount.toLocaleString()}. Narrow the time range or add filters to see the rest.`,
                warningSeverity: 'info',
              });
            }
          }
          setIsSearching(false);
          setHasSearched(true);
          queryClient.invalidateQueries({ queryKey: ['search-jobs'] });
        } else if (status.status === 'failed') {
          clearAsyncJob();
          setIsSearching(false);
          queryClient.invalidateQueries({ queryKey: ['search-jobs'] });
          // Detect parse errors from async job failures (error message starts with "Parse error" or contains position info)
          const errorMsg = status.error || 'Search job failed';
          // NAN-4915: typed background-job failures map to a stable code the
          // error banner can explain (time limit, too large, worker lost).
          const errCode = jobFailureCode(errorMsg, status.durable?.error_kind);
          setSearchError({ code: errCode, message: errorMsg });
          requestQueryCorrection(errCode, errorMsg, query);
        } else if (status.status === 'cancelled') {
          clearAsyncJob();
          setIsSearching(false);
          queryClient.invalidateQueries({ queryKey: ['search-jobs'] });
        }
      } catch (err) {
        console.error('Error polling job status:', err);
        // Continue polling - job might still be running
      }
    }, pollInterval);
  }, [clearAsyncJob, processAsyncJobResult, queryClient]);

  // Start streaming search via SSE (replaces async polling for better UX)
  const startStreamingSearch = useCallback((
    request: { query: string; time_range: import('@/lib/api/types').TimeRange; limit: number; offset: number; skip_field_stats: boolean; table_view?: boolean; dataset?: import('@/lib/api/types').SearchDataset },
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
      executionTimeMs: number | null;
      timing: SearchTimingBreakdown | null;
      displayType: import('@/lib/api/types').DisplayType | undefined;
      columnOrder: string[] | undefined;
      generatedSql: string | null;
      costScore: number | null;
    } = {
      histogramData: [],
      totalCount: 0,
      executionTimeMs: null,
      timing: null,
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
            timestamp: parseUTCTimestamp(r?.timestamp as string),
            source: resultRowSource(r),
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
        if (data.generated_sql) setGeneratedSql(data.generated_sql);
        const timing = searchTimingBreakdown(data);
        setExecutionTimeMs(timing.displayTimeMs);
        setSearchTiming(timing);
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
          executionTimeMs: timing.displayTimeMs,
          timing,
          displayType: data.display_type,
          columnOrder: data.column_order,
          generatedSql: data.generated_sql ?? null,
          costScore: data.cost_score ?? null,
        };
        // Handle warnings
        if (data.warnings && data.warnings.length > 0) {
          const errorWarning = data.warnings.find(w => w.severity === 'error');
          const warningWarning = data.warnings.find(w => w.severity === 'warning');
          const mainWarning = errorWarning || warningWarning || data.warnings[0];
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
          const cacheEntry: CachedSearchResult = {
            results: finalResults,
            histogramData: streamedMetadata.histogramData,
            serverFieldStats: null,
            fieldStatsReduced: null,
            totalCount: streamedMetadata.totalCount || data.total_rows_delivered || finalResults.length,
            executionTimeMs: streamedMetadata.executionTimeMs,
            timing: streamedMetadata.timing,
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
          // NAN-1508/1509: the streaming path is the default piped-search path —
          // apply the same auto-load gate. Small specific result set → full
          // inventory directly; broad/unknown → reduced. Reliable count only:
          // raw streamedMetadata.totalCount (absent/0 → safe reduced path).
          const fsSmall = (streamedMetadata.totalCount ?? 0) > 0 && (streamedMetadata.totalCount ?? 0) < AUTO_SHOW_ALL_RESULT_THRESHOLD;
          fetchFieldStats({ ...fsRequest, columns: fsSmall ? undefined : collectFieldStatsColumns(searchResultsRef.current), signal: runControllerRef.current?.signal })
            .then(fieldStatsResponse => {
              if (fieldStatsResponse.fields && fieldStatsResponse.fields.length > 0) {
                setServerFieldStats(fieldStatsResponse.fields);
                setFieldStatsReduced(!fsSmall);
                // NAN-1509: persist field stats + reduced flag to the cache entry
                // so a cached restore keeps the teaser/auto-fetch behavior.
                if (cacheKey) {
                  const cached = searchResultCache.get(cacheKey);
                  if (cached) {
                    cached.serverFieldStats = fieldStatsResponse.fields;
                    cached.fieldStatsReduced = !fsSmall;
                  }
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
        if (data.code === 'NETWORK_ERROR' || data.code === 'NO_BODY' || data.code === 'HTTP_ERROR') {
          console.warn('SSE streaming failed, falling back to async polling:', data.message);
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
      // NAN-4915: the search outran the interactive budget and continues as a
      // durable background job. Rows streamed so far are superseded — clear
      // them and attach to the job (progress, then the stored result).
      onJob: (job) => {
        rowBatch = [];
        setIsStreamingResults(false);
        sseControllerRef.current = null;
        setSearchResults([]);
        setAsyncJobId(job.job_id);
        setAsyncJobStatus(job.status);
        queryClient.invalidateQueries({ queryKey: ['search-jobs'] });
        startAsyncJobPolling(job.job_id, currentQuery, currentTimeRange, currentMode, isAggregate, request.dataset);
      },
    }, { bypass: bypassCache, acceptAsync: true });

    sseControllerRef.current = controller;
  }, [clearAsyncJob, processAsyncJobResult, startAsyncJobPolling, queryClient, fetchFieldStats, toApiTimeRange, captureSearch, requestQueryCorrection]);

  // Main search function
  const handleSearch = useCallback(async (page: number = 1, append: boolean = false, searchQuery?: string, searchMode?: 'piped' | 'sql', searchTimeRange?: TimeRangeValue, useCache?: boolean, searchDataset?: import('@/lib/api/types').SearchDataset) => {
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
    // NAN-5235: this tab ran it, so a reload or back-navigation may re-run it.
    rememberTabSearch(currentQuery);
    setLinkedRunPending(false);

    // NAN-173: Block SQL execution without permission
    if (currentMode === 'sql' && !canSql) {
      setSearchError({ code: 'PERMISSION_DENIED', message: 'Raw SQL queries require the search:sql permission. Contact your administrator.' });
      return;
    }

    // NAN-3883: one user action, one search. The duplicate runs came from the
    // page re-reading its OWN URL write (and router lag) as navigation; that
    // origin is suppressed in the URL-sync effect (prevUrlRef / seenUrlRef).
    // Every deliberate trigger runs — no fuzzy coalescing of similar inputs,
    // which could swallow a live run behind a passive cached load.

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
    setDisplayType(undefined);
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
      // NAN-4915: a fresh search detaches from the previous job's rows.
      jobContinuationRef.current = null;
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
      tailSearchRanAtRef.current = Date.now();
      setServerFieldStats(null);
      setFieldStatsReduced(false);
      setPeakRowsScanned(0);
      // The timeline belongs to the exact query + window. A different search
      // starts from an empty chart so it never shows the previous search's
      // buckets; NAN-3273: a re-run of the same search (only the window moved)
      // keeps showing the last timeline until the replacement lands.
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
      const offset = (page - 1) * pageSize;
      let response;
      
      // Strip comments from query before sending to API
      let cleanQuery = stripComments(currentQuery);

      // Inject prevalence filter if active (piped mode only). Must go *before* any
      // pipeline commands — `stats`/`table`/`timechart`/etc. project away
      // `prevalence_min`, so appending to the end breaks with UNKNOWN_IDENTIFIER
      // in later stages. Rarity is always an event-level filter, so it belongs
      // right after the search expression.
      if (prevalenceMax < 100 && currentMode === 'piped') {
        cleanQuery = injectBeforeFirstPipe(cleanQuery, ` | where prevalence_min <= ${prevalenceMax}`);
      }

      // Use SSE streaming for initial piped searches (live results as ClickHouse returns them)
      // Falls back to async polling if SSE connection fails
      const shouldUseStreaming = currentMode === 'piped' && !append;

      if (currentMode === 'sql') {
        response = await searchSql({ sql: cleanQuery, time_range: apiTimeRange, limit: pageSize, offset });
      } else if (shouldUseStreaming) {
        // Use SSE streaming for live result delivery
        startStreamingSearch(
          { query: cleanQuery, time_range: apiTimeRange, limit: pageSize, offset, skip_field_stats: true, table_view: true, dataset: currentDataset },
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
        response = await search({ query: cleanQuery, time_range: apiTimeRange, limit: pageSize, offset, use_cache: useCache, skip_field_stats: true, skip_histogram: offset > 0, table_view: true, request_id: requestId, dataset: currentDataset });
      }

      if (abortControllerRef.current?.signal.aborted) return;

      const results: SearchResult[] = (response.results || [])
        .filter((r: unknown) => r != null && typeof r === 'object')
        .map((r: Record<string, unknown>, i: number) => ({
          id: `result-${offset + i}`,
          timestamp: parseUTCTimestamp(r?.timestamp as string),
          source: resultRowSource(r),
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
      if (!append) {
        if (effectiveTotalCount === 0) {
          // If we got exactly the limit, there's likely more data
          // Use a high estimate to enable pagination
          effectiveTotalCount = results.length >= pageSize ? results.length * 100 : results.length;
        }
        setTotalCount(effectiveTotalCount);
      } else if (response.total_count <= offset + pageSize) {
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
      }
      setCurrentPage(page);
      if (response.generated_sql) setGeneratedSql(response.generated_sql);
      const timing = searchTimingBreakdown(response);
      setExecutionTimeMs(timing.displayTimeMs);
      setSearchTiming(timing);
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
          const keyFields = results.slice(0, 3).map(r => {
            // NAN-5271: the row's own fields (OCSF paths on an OCSF row).
            return resultRowKeyFields(r.fields as Record<string, unknown>);
          }).filter(Boolean).join(' | ');

          updated[lastIdx] = {
            ...updated[lastIdx],
            result_summary: `Found ${resultCount.toLocaleString()} events`,
            key_context: keyFields || undefined,
          };
          return updated;
        });
      }
      
      // Handle query warnings by converting them to errors for consistent display
      if (response.warnings && response.warnings.length > 0) {
        // Find the most severe warning to display as the main error
        const errorWarning = response.warnings.find(w => w.severity === 'error');
        const warningWarning = response.warnings.find(w => w.severity === 'warning');
        const mainWarning = errorWarning || warningWarning || response.warnings[0];
        
        // Convert warning to error format for consistent display
        setSearchError({
          code: mainWarning.code,
          message: mainWarning.message,
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
      if (!append) {
        setHistogramData(histData);
      }

      // Cache results for back-navigation (use local vars, not state which is async)
      const cacheKey = !append ? buildCacheKey(currentQuery, currentTimeRange, currentMode, currentDataset) : null;
      if (cacheKey) {
        const cacheEntry: CachedSearchResult = {
          results,
          histogramData: histData,
          serverFieldStats: null,
          fieldStatsReduced: null,
          totalCount: effectiveTotalCount,
          executionTimeMs: timing.displayTimeMs,
          timing,
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
        // Small, specific result set → full inventory directly; broad → reduced.
        // effectiveTotalCount is already page-full-aware (estimates large when a
        // full page came back), so it never falsely reads as "small".
        const fsSmall = effectiveTotalCount > 0 && effectiveTotalCount < AUTO_SHOW_ALL_RESULT_THRESHOLD;
        fetchFieldStats({ ...fsRequest, columns: fsSmall ? undefined : collectFieldStatsColumns(results), signal: runControllerRef.current?.signal })
          .then(fieldStatsResponse => {
            if (fieldStatsResponse.fields && fieldStatsResponse.fields.length > 0) {
              setServerFieldStats(fieldStatsResponse.fields);
              setFieldStatsReduced(!fsSmall);
              // Update cache entry with field stats
              if (cacheKey) {
                const cached = searchResultCache.get(cacheKey);
                if (cached) {
                  cached.serverFieldStats = fieldStatsResponse.fields;
                  cached.fieldStatsReduced = !fsSmall;
                }
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
      if (err instanceof Error && err.name === 'AbortError') return;
      const searchErr = handleError(err, 'Unknown error');
      setSearchError(searchErr);
      requestQueryCorrection(searchErr.code, searchErr.message, query);
    } finally {
      // Don't clear isSearching if async polling or SSE streaming is active — their callbacks handle that
      if (!asyncJobPollingRef.current && !sseControllerRef.current) {
        setIsSearching(false);
      }
      setHasSearched(true);
    }
  }, [query, queryMode, timeRange, pageSize, search, searchSql, updateUrl, beginRunScope, addToSearchHistory, refreshHistory, captureSearch, prevalenceMax, showSql, explainQuery, startStreamingSearch, requestQueryCorrection, dataset]);

  /** The query a tail read sends: comments stripped, rarity filter applied. */
  const tailRequestQuery = useCallback((tailQuery: string): string => {
    let cleanQuery = stripComments(tailQuery);
    if (prevalenceMax < 100 && queryMode === 'piped') {
      cleanQuery = injectBeforeFirstPipe(cleanQuery, ` | where prevalence_min <= ${prevalenceMax}`);
    }
    return cleanQuery;
  }, [prevalenceMax, queryMode]);

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
   * and make it the live count. Local arrival counting drifts (a poll page can
   * miss late inserts) and bucket-granular roll-off saw-tooths; the server
   * read has neither problem. At most one in flight; a failure is silent and
   * the next due tick retries. The URL follows the anchored window, so a
   * reload or a copied link reproduces what is on screen.
   *
   * This build has no histogram-only route, so the anchor is a one-row search
   * whose histogram companion is the read (field stats skipped).
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
    const anchorEndMs = nowMs;
    const windowStart = new Date(anchorEndMs - spanMs).toISOString();
    const windowEnd = new Date(anchorEndMs).toISOString();
    const epoch = tailEpochRef.current;
    const controller = new AbortController();
    anchor.lastRequestedMs = nowMs;
    anchor.controller = controller;
    search({
      query: tailRequestQuery(tailQuery),
      time_range: { start: windowStart, end: windowEnd },
      limit: 1,
      offset: 0,
      skip_field_stats: true,
      table_view: true,
      dataset,
    })
      .then(result => {
        if (controller.signal.aborted || tailEpochRef.current !== epoch) return;
        const histogram = (result as { histogram?: Array<{ time: string; count: number }> } | undefined)?.histogram;
        // NAN-3267: the live "N events" is this timeline's sum. An empty or
        // zero-filled read must not blank it; keep the last known timeline
        // (the tail keeps counting into it) until a read carries real data.
        if (!histogram || !tailReanchorTrusted(histogram, histogramDataRef.current, {
          anchorStartMs: anchorEndMs - spanMs,
          anchorEndMs,
        })) return;
        const landedMs = Date.now();
        const next = reanchorTailHistogram(histogram, tailArrivalLogRef.current, {
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
    advanceTailTimelineRef.current(fresh.map(row => row.timestamp.getTime()));
  }, []);

  /**
   * One live-tail tick (NAN-2551).
   *
   * Prepends the rows that arrived since the last tick. It deliberately does
   * NOT re-enter `handleSearch`: the tail must not touch pagination, the URL,
   * search history, the AI refinement conversation or a dismissed warning.
   * Aggregates and raw SQL have no scroll state and no per-event identity to
   * prepend against, so they keep the whole-window re-run, which is the
   * correct refresh for them.
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

    // NAN-2557: the tick outlives its own `await`; a fresh search started
    // while it is in flight resets the tail, and the late tick must not seed
    // the new query's seen-key set or prepend the old query's arrivals.
    const epoch = tailEpochRef.current;
    const pollStartedAt = Date.now();
    tailPollStartedAtRef.current = pollStartedAt;
    try {
      const nowMs = Date.now();
      const cleanQuery = tailRequestQuery(tailQuery);
      const isoMs = (ms: number) => new Date(ms).toISOString();

      // One tail read. `tie` pages a single millisecond in a stable (event id)
      // order by offset; `extra` appends a pipeline stage (the arming seed's
      // ingest-time bound). `null` = no rows this time (escalated / superseded).
      const readTail = async (
        startMs: number, endMs: number, opts: { offset?: number; tie?: boolean; extra?: string } = {},
      ): Promise<Record<string, unknown>[] | null> => {
        if (tailEpochRef.current !== epoch) return null;
        let pageQuery = cleanQuery;
        if (opts.extra) pageQuery = `${pageQuery} ${opts.extra}`;
        if (opts.tie) pageQuery = `${pageQuery} | sort -id`;
        const response = await search({
          query: pageQuery,
          time_range: { start: isoMs(startMs), end: isoMs(endMs) },
          limit: TAIL_FETCH_LIMIT,
          offset: opts.offset ?? 0,
          skip_field_stats: true,
          // NAN-1645 precedent: a tail tick is not a new result set, so it
          // neither pays for a histogram nor replaces the one being read.
          skip_histogram: true,
          table_view: true,
          dataset,
        });
        const rows = (response as { results?: unknown } | undefined)?.results;
        if (!Array.isArray(rows)) {
          // Admission escalated this page to a durable job. A tail page is
          // never worth a job; cancel it and let the next tick retry (the
          // watermark does not move, so nothing is lost).
          const jobId = (response as { job_id?: string } | undefined)?.job_id;
          if (jobId) api.cancelSearchJob(jobId).catch(() => {});
          return null;
        }
        return (rows as unknown[]).filter(
          (r): r is Record<string, unknown> => r != null && typeof r === 'object',
        );
      };
      const rowTimeMs = (row: Record<string, unknown>) => tailRowTimestamp(row).getTime();

      if (tailWatermarkRef.current === 0) {
        // Arm against what is on screen: its keys suppress the overlap's
        // re-delivery, its newest event time anchors the window. NAN-2557: that
        // is the tail's own rows as well as the paged set.
        const base = tailArmRows(tailStateRef.current, searchResultsRef.current);
        const armedAt = tailWatermark(base, tailWindow(nowMs, nowMs, tailInterval).startMs, nowMs);
        const seenAtArm = new Set(tailSeenKeysRef.current);
        rememberTailKeys(seenAtArm, base);
        // NAN-4927 review: the lookback window also holds rows the search
        // already counted but that sit below the loaded page. They are part of
        // the initial result set, not arrivals; the ones that existed when the
        // search ran (ingest time at or before its start) seed the dedupe keys.
        // A row ingested later with an old event time is NOT seeded, so the
        // next polls still deliver it (the late-insert lookback).
        // Without a known run start (a result set restored from somewhere
        // other than a run) every lookback row seeds: never re-count.
        const ranAt = tailSearchRanAtRef.current;
        if (base.length > 0) {
          const seedWindow = { startMs: tailWindow(armedAt, nowMs, tailInterval).startMs, endMs: armedAt };
          const ingestBound = new Date(ranAt).toISOString().replace('T', ' ').replace('Z', '');
          const extra = ranAt > 0 ? `| where _inserted_at <= "${ingestBound}"` : undefined;
          const seed = await collectTailPages<Record<string, unknown>>({
            window: seedWindow,
            cursorMs: seedWindow.startMs,
            rowTimeMs,
            fetchPage: (w) => readTail(w.startMs, w.endMs, { extra }),
            fetchTied: (instantMs, offset) => readTail(instantMs, instantMs, { extra, offset, tie: true }),
          });
          if (tailEpochRef.current !== epoch) return;
          // Not seeded yet: stay unarmed, the next tick tries again.
          if (!seed.complete && !seed.capped) return;
          rememberTailKeys(seenAtArm, seed.rows.map((r, i) => ({ id: `seed-${i}`, fields: r })));
        }
        tailSeenKeysRef.current = seenAtArm;
        tailWatermarkRef.current = armedAt;
      }
      const askFor = tailWindow(tailWatermarkRef.current, nowMs, tailInterval);
      const cursorMs = tailWatermarkRef.current;

      // NAN-3264: page down from now to the cursor, so a burst bigger than one
      // page leaves no hole below the newest page. NAN-4927 review: a burst
      // that shares one millisecond is drained by offset in event-id order.
      const polled = await collectTailPages<Record<string, unknown>>({
        window: askFor,
        cursorMs,
        rowTimeMs,
        fetchPage: (w) => readTail(w.startMs, w.endMs),
        fetchTied: (instantMs, offset) => readTail(instantMs, instantMs, { offset, tie: true }),
      });

      // NAN-2557: superseded while awaiting.
      if (tailEpochRef.current !== epoch) return;

      const mapped: SearchResult[] = polled.rows.map((r, i) => ({
        // Not `result-N`: tail ids must not collide with the offset-derived
        // ids of the paged set they sit in front of.
        id: `tail-${nowMs}-${i}`,
        timestamp: tailRowTimestamp(r),
        source: tailRowSource(r),
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
      // window. Never surface it as a search error, which auto-stops the tail.
    } finally {
      if (tailPollStartedAtRef.current === pollStartedAt) tailPollStartedAtRef.current = 0;
    }
  }, [timeRange, queryMode, isAggregateQuery, displayType, handleSearch, executedQuery, query,
      tailInterval, tailRequestQuery, search, dataset, foldTailArrivals]);

  useEffect(() => { runTailRefreshRef.current = () => { void runTailRefresh(); }; }, [runTailRefresh]);

  /** The "N new events" chip: show the arrivals held back while scrolled away. */
  const showBufferedTailRows = useCallback(() => {
    setTailState(current => flushTailBuffer(current));
    resultsScrollContainer?.current?.scrollTo({ top: 0, behavior: 'smooth' });
  }, [resultsScrollContainer]);

  // Tail arrivals render in front of the paged result set (NAN-2551).
  const displayResults = useMemo(
    () => (tailState.rows.length > 0 ? [...tailState.rows, ...searchResults] : searchResults),
    [tailState.rows, searchResults],
  );

  // NAN-4589: pivt analyzes the results on screen in its panel (Analyze
  // button, `@summarize [focus]`). The page hands pivt the run the rows came
  // from through a getter, read when a run starts; the results area is never
  // replaced. Open builds get an inert stub.
  const analysisSourceRef = useRef<() => SearchAnalysisContext | { unavailable: string }>(() => ({ unavailable: '' }));
  analysisSourceRef.current = () => {
    if (isSearching) return { unavailable: 'The search is still running. Wait for results, then ask again.' };
    if (!hasSearched || displayResults.length === 0) {
      return { unavailable: NO_SEARCH_TO_ANALYZE };
    }
    const scope = runScopeRef.current;
    const scopeTime = scope?.timeRange ?? timeRange;
    return {
      query: executedQuery || query,
      queryMode,
      dataset,
      timeRange: scopeTime,
      range: scope?.range ?? toApiTimeRange(scopeTime),
      results: displayResults.slice(0, MAX_ANALYZE_ROWS).map((r) => r.fields),
      totalCount: displayTotalCount,
      histogram: histogramData,
    };
  };
  useEffect(() => registerSearchAnalysisSource(() => analysisSourceRef.current()), []);
  const analyzeInPivt = useCallback(() => {
    openPivtPanel();
    void startSearchAnalysis('');
  }, []);

  const handleStopSearch = useCallback(() => {
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

  // NAN-4915: rows of a completed background job, mapped like any search page.
  const jobRowsToResults = useCallback((rows: Record<string, unknown>[], startIndex: number): SearchResult[] =>
    rows
      .filter((r: unknown) => r != null && typeof r === 'object')
      .map((r: Record<string, unknown>, i: number) => ({
        id: `result-${startIndex + i}`,
        timestamp: parseUTCTimestamp(r?.timestamp as string),
        source: resultRowSource(r),
        fields: r,
      })), []);

  const loadMore = useCallback(() => {
    if (isSearching || searchResults.length >= totalCount) return;
    // NAN-4915: continuation — page the completed job's stored rows instead
    // of re-running a search that already needed a background job.
    const continuation = jobContinuationRef.current;
    if (continuation) {
      const next = nextContinuationPage(searchResults.length, continuation.rowCount, pageSize);
      if (!next) return; // stored result exhausted (cap reached)
      const { offset } = next;
      setIsSearching(true);
      api.getSearchJobResults(continuation.jobId, offset, next.limit)
        .then(page => {
          if (jobContinuationRef.current?.jobId !== continuation.jobId) return;
          setSearchResults(prev => [...prev, ...jobRowsToResults(page.rows, offset)]);
        })
        .catch(err => {
          jobContinuationRef.current = null;
          setSearchError(handleError(err, 'Could not load more results from the background search'));
        })
        .finally(() => setIsSearching(false));
      return;
    }
    handleSearch(currentPage + 1, true);
  }, [isSearching, searchResults.length, totalCount, currentPage, handleSearch, pageSize, jobRowsToResults]);

  // Handler for table pagination - fetches page from server
  const handleTablePageChange = useCallback(async (newPage: number, overrideSize?: number) => {
    const effectiveSize = overrideSize ?? tablePageSize;
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
    if (overrideSize === undefined && searchResults.length >= totalCount) {
      setTablePage(newPage);
      return;
    }

    // NAN-4915: a completed background job's rows are paged from the job,
    // never by re-running the search.
    const continuation = jobContinuationRef.current;
    if (continuation) {
      const offset = newPage * effectiveSize;
      // Codex P2-7: never request a page past the job's stored rows.
      if (!isPageInStoredRange(offset, continuation.rowCount)) return;
      setIsSearching(true);
      try {
        const page = await api.getSearchJobResults(continuation.jobId, offset, effectiveSize);
        if (jobContinuationRef.current?.jobId !== continuation.jobId) return;
        setSearchResults(jobRowsToResults(page.rows, offset));
        setTablePage(newPage);
      } catch (err) {
        // The API answers an out-of-range or still-replicating page with a
        // non-200; keep the current rows and say why instead of blanking them.
        setSearchError(handleError(err, 'Could not load that page of the background search'));
      } finally {
        setIsSearching(false);
      }
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
        cleanQuery = injectBeforeFirstPipe(cleanQuery, ` | where prevalence_min <= ${prevalenceMax}`);
      }

      const response = queryMode === 'sql'
        ? await searchSql({ sql: cleanQuery, time_range: apiTimeRange, limit: effectiveSize, offset })
        : await search({ query: cleanQuery, time_range: apiTimeRange, limit: effectiveSize, offset, skip_field_stats: true, skip_histogram: offset > 0, dataset });

      if (abortControllerRef.current?.signal.aborted) return;

      const results: SearchResult[] = (response.results || [])
        .filter((r: unknown) => r != null && typeof r === 'object')
        .map((r: Record<string, unknown>, i: number) => ({
          id: `result-${offset + i}`,
          timestamp: parseUTCTimestamp(r?.timestamp as string),
          source: resultRowSource(r),
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
  }, [isAggregateQuery, displayType, executedQuery, searchResults.length, timeRange, tablePageSize, totalCount, queryMode, prevalenceMax, search, searchSql, dataset, jobRowsToResults]);

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
      // NAN-5235: a shared link opened from outside the app loads the search
      // and waits for Run, like any other outside link.
      if (!mayRunUrlQueryAt(routerLocationRef.current, shared.query)) {
        setLinkedRunPending(true);
        return;
      }
      setTimeout(() => handleSearch(1, false, shared.query, shared.query_mode as 'piped' | 'sql', loadedTimeRange, true), 100);
    } catch (err) {
      setSearchError(handleError(err, 'Failed to load shared search'));
    }
  }, [getSharedSearch, handleSearch]);

  // AI Query Builder - uses natural language input to generate piped query
  // isRefinement: true when this is a follow-up query in a conversation
  const handleAskMelod = useCallback(async (overrideQuery?: string, isRefinement = false) => {
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
          // Store the explanation in the cache for URL sharing
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
  }, [naturalLanguageQuery, timeRange, buildQueryJob, handleSearch, storeQueryExplanation, userQueryMode, aiConversationHistory]);

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
              timestamp: parseUTCTimestamp(r?.timestamp as string),
              source: resultRowSource(r),
              fields: (r && typeof r === 'object') ? r : {},
            }));
          
          setSearchResults(results);
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
  // window the rows were read from.
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

  // Timeline data - prefer histogram from API, fallback to building from results
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

  // Field stats - prefer server-provided stats (from topK across ALL matching events)
  // Fall back to client-side stats for aggregate queries or when server stats unavailable
  const fieldStats = useMemo<FieldStat[]>(() => {
    // Prefer server-provided field stats (more accurate - computed across all matching events)
    if (serverFieldStats && serverFieldStats.length > 0) {
      return serverFieldStats.map(field => {
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
          }))
        };
      // Fields whose every value is empty are noise, and internal helper
      // columns aren't schema fields — don't surface either.
      }).filter(stat => stat.count > 0 && stat.topValues.length > 0 && !isInternalHelperField(stat.field));
    }

    // Fall back to client-side calculation (for aggregate queries or when server stats unavailable)
    if (!searchResults || searchResults.length === 0) return [];

    // Collect all flattened field values across all results
    const fieldValueCounts = new Map<string, Map<string, number>>();

    for (const result of searchResults) {
      if (result?.fields && typeof result.fields === 'object' && result.fields !== null) {
        const flattenedFields = flattenFieldsForStats(result.fields);

        for (const [field, value] of flattenedFields) {
          // Only count scalar values (not objects/arrays)
          if (typeof value === 'object' && value !== null) continue;
          // Empty/null is "field absent", not a value (mirrors the server-
          // stats path above; String(null) would otherwise count as "null")
          if (value === null || value === undefined || value === '') continue;
          if (isInternalHelperField(field)) continue;

          const valueStr = String(value);

          if (!fieldValueCounts.has(field)) {
            fieldValueCounts.set(field, new Map());
          }
          const valueCounts = fieldValueCounts.get(field)!;
          valueCounts.set(valueStr, (valueCounts.get(valueStr) || 0) + 1);
        }
      }
    }

    // Convert to FieldStat array
    return Array.from(fieldValueCounts.entries()).map(([field, valueCounts]) => {
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
  }, [serverFieldStats, searchResults]);

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
    if (!isAuthenticated || extFieldsFetchedRef.current) return;
    extFieldsFetchedRef.current = true;
    // NAN-5265: the API returns BARE spill keys; register the namespaced form
    // the fields panel shows (`ext.x` / `unmapped.x`) plus the bare key, which
    // both profiles also resolve into the spill.
    Promise.all([api.getExtFieldNames(), api.getSchemaFields().catch(() => null)])
      .then(([names, schema]) => {
        if (names.length > 0) {
          const isOcsf = schema?.schema === 'ocsf';
          registerDynamicFields([...names, ...names.map((n) => spillFieldName(n, isOcsf))]);
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
      consumeSearchAutoRun(urlRunToken);
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

  // NAN-5235: a `run` param without a grant (an external link, a bookmark, a
  // legacy `run=true`) never forces a run. Drop it from the URL; the
  // passive-load effect below decides, and prompts on an outside arrival.
  useEffect(() => {
    if (!urlRunUngranted) return;
    if (!mayRunUrlQueryOnArrival(urlQuery)) setLinkedRunPending(true);
    const params = new URLSearchParams(searchParams);
    params.delete('run');
    params.delete('ai');
    prevUrlRef.current = params.toString();
    setSearchParams(params, { replace: true });
  }, [urlRunUngranted]); // eslint-disable-line react-hooks/exhaustive-deps

  // Load results from a completed async job (e.g. from ActiveSearchesPanel or notification link)
  const lastJobIdRef = useRef<string | null>(null);
  useEffect(() => {
    if (!urlJobId || lastJobIdRef.current === urlJobId) return;
    lastJobIdRef.current = urlJobId;

    (async () => {
      try {
        setIsSearching(true);
        setFieldsPanelVisible(true);
        const status = await api.getSearchJob(urlJobId);

        if (status.status === 'completed' && status.result) {
          processAsyncJobResult(
            status.result,
            status.result.generated_sql || urlQuery || 'Loaded from job',
            timeRange,
            queryMode as 'piped' | 'sql',
            false,
          );
          // NAN-4915: attached to a finished background job — page its
          // stored rows from here on.
          if (status.durable) {
            const rowCount = status.durable.row_count ?? status.result.results.length;
            jobContinuationRef.current = { jobId: urlJobId, rowCount };
            if (status.durable.result_truncated) {
              setTotalCount(pageableRowCount(status.result.total_count, rowCount, true));
            }
          }
          setIsSearching(false);
          setHasSearched(true);
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
  }, [urlJobId]); // eslint-disable-line react-hooks/exhaustive-deps

  // Effects
  useEffect(() => {
    if (urlShortId && !hasSearched) {
      loadSharedSearch(urlShortId);
    } else if (urlQuery && !hasSearched && !urlAutoRun) {
      // Show fields panel since we have a query to execute
      setFieldsPanelVisible(true);
      
      // Try to fetch cached explanation for this query
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
      
      // NAN-5235: a URL query runs on arrival only from an in-app navigation
      // or if this tab already ran it (reload, back/forward). A link from
      // outside the app loads the query and asks for an explicit Run.
      if (!mayRunUrlQueryOnArrival(urlQuery)) {
        setLinkedRunPending(true);
        return;
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
  // the new one and ran it again. Only a location the router has actually
  // delivered can be navigation.
  const seenUrlRef = useRef(searchParams.toString());
  useEffect(() => {
    const currentUrlStr = searchParams.toString();
    if (currentUrlStr === seenUrlRef.current) return;
    seenUrlRef.current = currentUrlStr;
    // Only process if URL actually changed (back/forward navigation)
    if (currentUrlStr === prevUrlRef.current) return;
    prevUrlRef.current = currentUrlStr;
    
    const currentUrlQuery = searchParams.get('q') || '';
    const currentUrlMode = (searchParams.get('mode') as 'piped' | 'sql' | 'natural') || 'piped';
    // NAN-1825: restore the dataset from the URL too — back-nav across a
    // dataset boundary (logs ↔ spans/metrics/risk) must re-run against the
    // dataset that search actually targeted.
    const rawUrlDataset = searchParams.get('dataset');
    const urlDataset: import('@/lib/api/types').SearchDataset =
      rawUrlDataset === 'spans' || rawUrlDataset === 'metrics' || rawUrlDataset === 'risk' ? rawUrlDataset : 'logs';
    
    // Build time range from URL
    const historyTimeRange: TimeRangeValue = readTimeRangeParams(searchParams)
      ?? { type: 'preset', preset: 'Last hour' };
    
    // Normalize mode (convert old 'natural' to 'piped')
    const normalizedMode = currentUrlMode === 'natural' ? 'piped' : currentUrlMode as 'piped' | 'sql';
    
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
      
      // NAN-5235: a history entry this app did not create (a fragment
      // navigation another window performed on this tab) loads its query
      // and waits for Run; it never executes on its own.
      const urlChangeMayRun = mayRunUrlQueryAt(routerLocation, currentUrlQuery);
      if (currentUrlQuery.trim() && currentUrlMode !== 'natural' && !urlChangeMayRun) {
        setSearchResults([]);
        setHistogramData([]);
        setServerFieldStats(null);
        setHasSearched(false);
        setLinkedRunPending(true);
        setTimeout(() => {
          isRestoringFromHistory.current = false;
        }, 50);
      } else if (currentUrlQuery.trim() && currentUrlMode !== 'natural') {
        // If there's a query in the URL, check cache first, then fall back to search
        const cacheKey = buildCacheKey(currentUrlQuery, historyTimeRange, normalizedMode, urlDataset);
        // NAN-3884: a relative range in the URL (`time=Last 7 days`) means
        // "re-resolve against now", so back-nav re-runs it, as it did when
        // the URL always carried fixed bounds. Only a fixed window restores
        // from cache.
        const cached = historyTimeRange.type === 'custom' ? searchResultCache.get(cacheKey) : undefined;
        if (cached && (Date.now() - cached.cachedAt) < CACHE_TTL_MS) {
          // NAN-3884: the restored rows' window is this URL's, so the meta row
          // and later pages read these bounds, not the previous run's.
          const restoredScope: SearchRunScope = { timeRange: historyTimeRange, range: toApiTimeRange(historyTimeRange) };
          runScopeRef.current = restoredScope;
          setRunScope(restoredScope);
          // Restore from cache — instant back-navigation
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
          setExecutionTimeMs(cached.executionTimeMs);
          setSearchTiming(cached.timing ?? null);
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
        setHistogramData([]);
        setServerFieldStats(null);
        setFieldStatsReduced(false);
        setTotalCount(0);
        setPeakRowsScanned(0);
        setExecutionTimeMs(null);
        setSearchTiming(null);
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
  }, [searchParams, query, queryMode, timeRange, dataset, handleSearch]);

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
    return () => {
      if (abortControllerRef.current) abortControllerRef.current.abort();
      runControllerRef.current?.abort();
    };
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
                  if (canSql) {
                    setQueryMode('sql');
                  } else {
                    setQueryMode('piped');
                    setSearchError({ code: 'PERMISSION_DENIED', message: 'Raw SQL queries require the search:sql permission. Contact your administrator.' });
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
              onAiSearch={melodStatus?.connected ? () => handleAskMelod(query) : undefined}
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
                onClick={() => showAiSuggestion ? handleAskMelod(query) : handleSearch()}
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
            <button
              type="button"
              onClick={() => setSavedQueriesOpen(true)}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md border border-border bg-foreground/[0.02] text-muted-foreground hover:border-border/80 hover:text-foreground transition-colors whitespace-nowrap shrink-0"
            >
              <LayoutGrid className="w-[11px] h-[11px]" />
              Saved queries
            </button>

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
            {linkedRunPending && query?.trim() && (
              <span
                role="status"
                data-testid="linked-query-run-prompt"
                className="inline-flex items-center gap-1.5 font-mono text-[10.5px] text-muted-foreground whitespace-nowrap shrink-0"
              >
                linked query · review, then
                <button
                  type="button"
                  onClick={() => {
                    setLinkedRunPending(false);
                    handleSearch(1, false, query, queryMode, timeRange);
                  }}
                  className="px-1.5 py-0.5 rounded border border-border text-foreground hover:bg-foreground/[0.04]"
                >
                  Run
                </button>
              </span>
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

            <span aria-hidden className="mx-1.5 w-1 h-1 rounded-full bg-border shrink-0" />

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
                  <DropdownMenuItem
                    onSelect={() => createAndCopyShortUrl()}
                    disabled={isCreatingShortUrl || !query?.trim()}
                    className="gap-1.5 px-2 py-1 text-[12px]"
                  >
                    {isCreatingShortUrl ? <LoadingIcon className="w-[13px] h-[13px]" /> : <Link2 className="w-[13px] h-[13px]" />}
                    <span>Copy short URL</span>
                    <DropdownMenuShortcut>⌘⇧L</DropdownMenuShortcut>
                  </DropdownMenuItem>
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
            <span aria-hidden className="mx-1.5 w-1 h-1 rounded-full bg-border shrink-0" />
            <DatasetSelector value={dataset} onChange={setDataset} disabled={isSearching} />

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
                  const shortUrl = `${window.location.origin}${window.location.pathname}#s=${shortUrlId}`;
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
                {queryMode === 'piped' && query?.trim() && (
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
              navigate(`/search#job_id=${jobId}`);
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
        {!isTreeView && displayType !== 'timechart' && displayType !== 'ranked_bar' && displayType !== 'flow' && displayType !== 'asset' && displayType !== 'cloud' && displayType !== 'lateral' && displayType !== 'services' && displayType !== 'service' && displayType !== 'trace' && displayType !== 'metric' && displayType !== 'retro' && displayType !== 'baseline' && (
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
          results={searchResults}
          hasSearched={hasSearched}
          onArtifactFilter={(artifact, artifactType, _ts) => {
            // Route through handleDrilldown so the artifact filter reuses the
            // proven stats-drill path (deferred setQuery → updateUrl → search).
            // Calling handleSearch synchronously here raced the URL-sync effect,
            // which restored the pre-drill query and clobbered the filter.
            // Escape like the field=value drilldown builder — a log-derived
            // artifact with `"`/`\` must not break out of the quoted comparison.
            // Profile-aware columns (OCSF: file.hashes / process.file.hashes;
            // dst_endpoint.hostname, query.hostname, http_request.url.hostname)
            // — different classes keep the artifact in different fields.
            const artifactQuery =
              artifactType === 'hash'
                ? schemaFields.filterAny(['fileHash', 'processHash'], artifact)
                : schemaFields.filterAny(['destHost', 'dnsQuery', 'domain'], artifact);
            handleDrilldown({ _rawClause: artifactQuery });
          }}
          assetContext={assetContext}
          timeWindow="24h"
          resultCount={displayTotalCount}
          query={executedQuery}
          timeRange={apiTimeRange}
          plotRange={timelinePlotRange}
          urlRarityView={searchParams.get('view') === 'rarity'}
          onUrlRarityViewChange={setUrlRarityView}
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

        {/* Fields panel + Results area - Fields panel hidden for full-width visualizations */}
        {(() => {
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
              <div className="flex-1 min-w-0" ref={resultsAreaRef}>
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
                  {/* NAN-2551/NAN-2557: tail arrivals render in front of the
                      paged set; `displayTotalCount` keeps the infinite-scroll
                      bound (`results.length < totalCount`) honest. */}
                  <SearchResults
                    results={displayResults}
                    totalCount={displayTotalCount}
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
                    onLoadMore={loadMore}
                    onDrilldown={handleDrilldown}
                    currentPage={tablePage}
                    pageSize={tablePageSize}
                    onPageChange={handleTablePageChange}
                    onPageSizeChange={handleTablePageSizeChange}
                    notebookActive={notebookActive}
                    onAddToNotebook={addEntityToNotebook}
                    onAddAllEntitiesToNotebook={addEntitiesToNotebook}
                    onFetchLog={fetchLog}
                    columnOrder={columnOrder}
                    assetPrevalenceFilter={assetPrevalenceFilter}
                    timeRange={apiTimeRange}
                    melodEnabled={capabilities.melod && melodStatus?.connected === true}
                    onSummarize={analyzeInPivt}
                    asyncJobId={asyncJobId}
                    asyncJobStatus={asyncJobStatus}
                    asyncJobProgress={asyncJobProgress}
                    asyncJobInfo={asyncJobInfo}
                    queuePosition={queuePosition}
                    estimatedWait={estimatedWait}
                    onCancelAsyncJob={handleCancelAsyncJob}
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

      {/* Add to Dashboard Dialog */}
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
        executionTimeMs={footerExecutionTimeMs}
        timing={footerGated ? null : searchTiming}
        asyncJobProgress={asyncJobProgress}
        asyncJobStatus={asyncJobStatus}
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
