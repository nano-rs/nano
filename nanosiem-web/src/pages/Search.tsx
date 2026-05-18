// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState, useMemo, useRef, useCallback, useEffect } from 'react';
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
import { cn, injectBeforeFirstPipe, isClickHouseDefault, stripComments } from '@/lib/utils';
import {
  Search as SearchIcon,
  ChevronDown,
  Save,
  Code,
  Loader2,
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
import { PivtIcon } from '@/enterprise/icons/PivtIcon';
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
import { useIsMobile } from '@/hooks/use-mobile';
import { Sheet, SheetContent, SheetTitle } from '@/components/ui/sheet';
import { useNotebookCapture } from '@/enterprise/contexts/NotebookContext';
import { TimelineVisualization, FieldsPanel, SearchResults, SearchQueryInput, SavedQueriesPalette, SearchJobsModal, PrevalenceSlider, type FieldStat } from '@/components/search';
import { AnalyzeView } from '@/enterprise/components/search/AnalyzeView';
import { useHereCardOverride } from '@/contexts/PageContext';
import type { SearchJobSummary } from '@/lib/api';
import { registerDynamicFields } from '@/components/editor';
import { SearchDemoHint } from '@/components/DemoHints';
import { SearchStatsBar } from '@/components/search/SearchStatsBar';
import { AddToDashboardDialog } from '@/components/dashboard';

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
      // prevalence is only aggregate when NOT using enrich=true (which adds fields to each row)
      if (afterPipe.startsWith('prevalence') && !afterPipe.includes('enrich=true') && !afterPipe.includes('enrich = true')) {
        return true;
      }
    }
  }
  
  return false;
};

// Find the position of the first pipe command separator (outside regex patterns and quotes)
// Returns -1 if no pipe found
const findFirstPipePosition = (q: string): number => {
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
        // Check if this is a regex delimiter (preceded by = or !=)
        const before = q.substring(0, i).trimEnd();
        if (before.endsWith('=') || before.endsWith('!=')) {
          inRegex = true;
        }
      } else {
        // End of regex
        inRegex = false;
      }
      continue;
    }

    if (c === '|' && !inRegex && !inQuote) {
      // Found a pipe outside of regex and quotes - this is a command separator
      return i;
    }
  }

  // No pipe found
  return -1;
};

// Extract base query (before pipe commands), being careful not to split on | inside regex patterns or quotes
const getBaseSearch = (q: string) => {
  const pipePos = findFirstPipePosition(q);
  if (pipePos === -1) {
    return q.trim();
  }
  return q.substring(0, pipePos).trim();
};

// Extract pipe commands (from first | to end), being careful not to split on | inside regex patterns or quotes
const getPipeCommands = (q: string) => {
  const pipePos = findFirstPipePosition(q);
  if (pipePos === -1) {
    return '';
  }
  return q.substring(pipePos).trim();
};

// --- Client-side search result cache for back-navigation ---
// Module-level cache survives component unmount/remount during navigation

interface CachedSearchResult {
  results: SearchResult[];
  histogramData: Array<{ time: string; count: number }>;
  serverFieldStats: Array<{ name: string; count: number; top_values: [string, number][]; cardinality?: number }> | null;
  totalCount: number;
  executionTimeMs: number | null;
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

function buildCacheKey(query: string, timeRange: TimeRangeValue, mode: string): string {
  const timeKey = timeRange.type === 'custom' && timeRange.start && timeRange.end
    ? `${timeRange.start.toISOString()}_${timeRange.end.toISOString()}`
    : timeRange.preset;
  return `${mode}:${query}:${timeKey}`;
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
  const queryClient = useQueryClient();
  const { defaultTimeRange, queryMode: userQueryMode } = useUserPreferences();

  useDocumentTitle('Search');

  // Parse URL params
  const urlQuery = searchParams.get('q') || '';
  const urlMode = (searchParams.get('mode') as 'piped' | 'sql' | 'natural') || 'piped';
  const urlTimePreset = searchParams.get('time') || '';
  const urlTimeStart = searchParams.get('start') || '';
  const urlTimeEnd = searchParams.get('end') || '';
  const urlShortId = searchParams.get('s') || '';
  const urlAutoRun = searchParams.get('run') === 'true';
  const urlJobId = searchParams.get('job_id') || '';
  const urlAiMode = searchParams.get('ai') === 'true'; // Enable AI refinement mode
  const urlPrevalence = searchParams.get('prevalence') ? parseInt(searchParams.get('prevalence')!, 10) : 100;

  const getInitialTimeRange = (): TimeRangeValue => {
    if (urlTimeStart && urlTimeEnd) {
      return { type: 'custom', start: new Date(urlTimeStart), end: new Date(urlTimeEnd) };
    }
    if (urlTimePreset) {
      return { type: 'preset', preset: urlTimePreset };
    }
    // Use user's preferred default time range
    const displayPreset = timeRangePresetToDisplay[defaultTimeRange] || 'Last hour';
    return { type: 'preset', preset: displayPreset };
  };

  // Core state
  const [queryMode, setQueryMode] = useState<'piped' | 'sql'>(urlMode === 'natural' ? 'piped' : urlMode as 'piped' | 'sql');
  const [query, setQuery] = useState(urlQuery || '');
  const [executedQuery, setExecutedQuery] = useState(''); // Query that was actually executed (for highlighting)
  const [naturalLanguageQuery, setNaturalLanguageQuery] = useState(urlMode === 'natural' ? urlQuery : '');
  const [timeRange, setTimeRange] = useState<TimeRangeValue>(getInitialTimeRange());
  const [searchResults, setSearchResults] = useState<SearchResult[]>([]);
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
  const tailTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const tailSearchingRef = useRef(false);

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

  // Active search jobs indicator — drives the badge on the More (...) chip.
  const { data: activeJobs } = useQuery({
    queryKey: ['search-jobs'],
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

  // PIVT bridge — `@summarize` from anywhere in the app fires
  // `pivt:summarize`. Route to the Analyze view the same way the
  // toolbar button does. (Router navigates to /search first if the
  // user isn't here yet, so the listener is always mounted in time.)
  useEffect(() => {
    const handler = () => setAnalyzeActive(true);
    window.addEventListener('pivt:summarize', handler);
    return () => window.removeEventListener('pivt:summarize', handler);
  }, []);

  // Pagination state
  const [currentPage, setCurrentPage] = useState(1);
  const [totalCount, setTotalCount] = useState(0);
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
          tags: queryMode === 'sql' ? ['SQL'] : ['NPL'],
          lines: [
            { label: 'query', value: query || '— (empty)' },
            {
              label: 'results',
              value:
                totalCount > 0
                  ? `${totalCount.toLocaleString()} events`
                  : 'no matches',
            },
          ],
          suggestions:
            totalCount > 0
              ? ['Summarize these results', 'Pivot by src_ip', 'Create a detection from this query']
              : ['Widen the time range', 'Remove a filter', 'Summarize zero-result patterns'],
        }
      : null
  );

  // Query execution time
  const [executionTimeMs, setExecutionTimeMs] = useState<number | null>(null);
  
  // Query cost score (for display in error messages)
  const [_queryCostScore, setQueryCostScore] = useState<number | null>(null);

  // Cached results banner (shown when serving from back-navigation cache)
  const [cachedResultsTimestamp, setCachedResultsTimestamp] = useState<number | null>(null);
  
  // Histogram data from API
  const [histogramData, setHistogramData] = useState<Array<{ time: string; count: number }>>([]);

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
  
  
  // Share state
  const [copiedUrl, setCopiedUrl] = useState(false);
  const [copiedShortUrl, setCopiedShortUrl] = useState(false);
  const [isCreatingShortUrl, setIsCreatingShortUrl] = useState(false);
  const [shortUrlId, setShortUrlId] = useState<string | null>(urlShortId || null);
  const [showAddToDashboardDialog, setShowAddToDashboardDialog] = useState(false);

  // AI suggestion pill state
  const [showAiSuggestion, setShowAiSuggestion] = useState(false);
  const aiSuggestionTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // AI hint popup - shows once to educate users about natural language search
  const [showAiHint, setShowAiHint] = useState(false);

  // Detect tree visualization mode - hide fields panel when in tree mode
  const isTreeView = searchResults.length > 0 && searchResults[0]?.fields?._display_type === 'tree';

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
  const prevTimeRangeRef = useRef(timeRange);

  // Hooks
  const { mutate: search } = useSearch();
  const { mutate: searchSql } = useSearchSql();
  const { mutate: explainQuery, loading: explaining } = useExplainQuery();
  const { mutate: fetchFieldStats, loading: fieldStatsLoading } = useFieldStats();
  const { mutate: fetchSearchFieldValues } = useSearchFieldValues();
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

  // Permission checks - Requirements: 5.3
  const { user, hasPermission, isAuthenticated } = useAuth();
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

  // Show AI hint popup once when meloD is connected (stored in localStorage)
  useEffect(() => {
    if (!melodStatus?.connected) return;

    const hasSeenHint = localStorage.getItem('nanosiem_ai_hint_seen');
    if (hasSeenHint) return;

    // Show hint after a short delay
    const showTimer = setTimeout(() => {
      setShowAiHint(true);
      localStorage.setItem('nanosiem_ai_hint_seen', 'true');
    }, 1000);

    // Auto-hide after 6 seconds
    const hideTimer = setTimeout(() => {
      setShowAiHint(false);
    }, 7000);

    return () => {
      clearTimeout(showTimer);
      clearTimeout(hideTimer);
    };
  }, [melodStatus?.connected]);

  // URL management - pushHistory=true creates a new browser history entry (for back button)
  const updateUrl = useCallback((q: string, mode: 'piped' | 'sql', time: TimeRangeValue, shortId?: string, pushHistory: boolean = false, prevalence?: number) => {
    const params = new URLSearchParams();
    if (shortId) {
      params.set('s', shortId);
      setSearchParams(params, { replace: !pushHistory });
      return;
    }
    if (q) params.set('q', q);
    if (mode !== 'piped') params.set('mode', mode);
    // Always resolve to absolute timestamps so shared/refreshed URLs
    // reproduce the exact same time window (not "last N hours from now")
    const resolved = toApiTimeRange(time);
    params.set('start', resolved.start);
    params.set('end', resolved.end);
    // Add prevalence filter to URL if not default (100 = show all)
    if (prevalence !== undefined && prevalence < 100) {
      params.set('prevalence', prevalence.toString());
    }
    setSearchParams(params, { replace: !pushHistory });
  }, [setSearchParams]);

  // Share URL functions
  const getShareableUrl = useCallback(() => {
    const params = new URLSearchParams();
    if (query) params.set('q', query);
    if (queryMode !== 'piped') params.set('mode', queryMode);
    const resolved = toApiTimeRange(timeRange);
    params.set('start', resolved.start);
    params.set('end', resolved.end);
    if (prevalenceMax < 100) {
      params.set('prevalence', prevalenceMax.toString());
    }
    const baseUrl = window.location.origin + window.location.pathname;
    return params.toString() ? `${baseUrl}?${params.toString()}` : baseUrl;
  }, [query, queryMode, timeRange, prevalenceMax]);

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
        query,
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
    };
  }, []);

  // Keep ref in sync with isSearching so the tail timer callback reads fresh value
  useEffect(() => {
    tailSearchingRef.current = isSearching;
  }, [isSearching]);

  // Live tail polling effect
  useEffect(() => {
    if (tailTimerRef.current) {
      clearInterval(tailTimerRef.current);
      tailTimerRef.current = null;
    }

    if (!tailActive || !query?.trim()) return;

    tailTimerRef.current = setInterval(() => {
      if (tailSearchingRef.current) return;

      // Re-snap time range to "now"
      const tailTimeRange: TimeRangeValue = timeRange.type === 'preset'
        ? { ...timeRange, refreshedAt: Date.now() }
        : (() => {
            const duration = (timeRange.end!.getTime() - timeRange.start!.getTime());
            const now = new Date();
            return { type: 'custom' as const, start: new Date(now.getTime() - duration), end: now };
          })();

      handleSearch(1, false, undefined, undefined, tailTimeRange);
    }, tailInterval);

    return () => {
      if (tailTimerRef.current) {
        clearInterval(tailTimerRef.current);
        tailTimerRef.current = null;
      }
    };
  }, [tailActive, tailInterval]); // intentionally minimal deps — reads refs for fresh state

  // Auto-stop tail on query change
  const prevQueryRef = useRef(query);
  useEffect(() => {
    if (prevQueryRef.current !== query && tailActive) {
      setTailActive(false);
    }
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
    isAggregate: boolean
  ) => {
    const results: SearchResult[] = (response.results || [])
      .filter((r: unknown) => r != null && typeof r === 'object')
      .map((r: Record<string, unknown>, i: number) => ({
        id: `result-${i}`,
        timestamp: parseUTCTimestamp(r?.timestamp as string),
        source: r?.source_type === 'findings'
          ? (r?.metadata as Record<string, unknown>)?.risk_entity as string || 'finding'
          : (r?.src_host as string) || (r?.src_ip as string) || 'unknown',
        fields: (r && typeof r === 'object') ? r : {},
      }));

    setSearchResults(results);
    setExecutedQuery(currentQuery);
    setTotalCount(response.total_count || results.length);
    if (response.generated_sql) setGeneratedSql(response.generated_sql);
    if (response.execution_time_ms !== undefined) setExecutionTimeMs(response.execution_time_ms);
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
    const cacheKey = buildCacheKey(currentQuery, currentTimeRange, currentMode);
    const cacheEntry: CachedSearchResult = {
      results,
      histogramData: histData,
      serverFieldStats: null,
      totalCount: response.total_count || results.length,
      executionTimeMs: response.execution_time_ms ?? null,
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
      const apiTime = toApiTimeRange(currentTimeRange);
      fetchFieldStats({ query: currentQuery, start: apiTime.start, end: apiTime.end })
        .then(fieldStatsResponse => {
          if (fieldStatsResponse.fields && fieldStatsResponse.fields.length > 0) {
            setServerFieldStats(fieldStatsResponse.fields);
            // Update cache entry with field stats
            const cached = searchResultCache.get(cacheKey);
            if (cached) cached.serverFieldStats = fieldStatsResponse.fields;
          }
        })
        .catch(err => {
          console.warn('Failed to fetch field stats:', err);
        });
    }

    // Capture search in notebook (if active)
    const apiTime = toApiTimeRange(currentTimeRange);
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
          const fields: string[] = [];
          const event = r as unknown as Record<string, unknown>;
          if (event.src_ip) fields.push(`src_ip: ${event.src_ip}`);
          if (event.dst_ip) fields.push(`dst_ip: ${event.dst_ip}`);
          if (event.user) fields.push(`user: ${event.user}`);
          if (event.url) fields.push(`url: ${event.url}`);
          if (event.hostname) fields.push(`hostname: ${event.hostname}`);
          return fields.join(', ');
        }).filter(Boolean).join(' | ');

        updated[lastIdx] = {
          ...updated[lastIdx],
          result_summary: `Found ${resultCount.toLocaleString()} events`,
          key_context: keyFields || undefined,
        };
        return updated;
      });
    }
  }, [fetchFieldStats, captureSearch, toApiTimeRange, requestQueryReview]);

  // Start polling for async job results
  const startAsyncJobPolling = useCallback((
    jobId: string,
    currentQuery: string,
    currentTimeRange: TimeRangeValue,
    currentMode: 'piped' | 'sql',
    isAggregate: boolean
  ) => {
    // Clear any existing polling interval to prevent leaks
    if (asyncJobPollingRef.current) {
      clearInterval(asyncJobPollingRef.current);
      asyncJobPollingRef.current = null;
    }

    const pollInterval = 1000; // 1 second
    const maxPolls = 300; // 5 minute timeout
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
          processAsyncJobResult(status.result, currentQuery, currentTimeRange, currentMode, isAggregate);
          setIsSearching(false);
          setHasSearched(true);
          queryClient.invalidateQueries({ queryKey: ['search-jobs'] });
        } else if (status.status === 'failed') {
          clearAsyncJob();
          setIsSearching(false);
          queryClient.invalidateQueries({ queryKey: ['search-jobs'] });
          // Detect parse errors from async job failures (error message starts with "Parse error" or contains position info)
          const errorMsg = status.error || 'Search job failed';
          const isParseError = /^(Parse error|Query parse error|Unexpected|Expected)/.test(errorMsg);
          const errCode = isParseError ? 'PARSE_ERROR' : 'JOB_FAILED';
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
    request: { query: string; time_range: import('@/lib/api/types').TimeRange; limit: number; offset: number; skip_field_stats: boolean; table_view?: boolean },
    currentQuery: string,
    currentTimeRange: TimeRangeValue,
    currentMode: 'piped' | 'sql',
    isAggregate: boolean
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
      displayType: import('@/lib/api/types').DisplayType | undefined;
      columnOrder: string[] | undefined;
      generatedSql: string | null;
      costScore: number | null;
    } = {
      histogramData: [],
      totalCount: 0,
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
            timestamp: parseUTCTimestamp(r?.timestamp as string),
            source: r?.source_type === 'findings'
              ? (r?.metadata as Record<string, unknown>)?.risk_entity as string || 'finding'
              : (r?.src_host as string) || (r?.src_ip as string) || 'unknown',
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
          executionTimeMs: data.execution_time_ms ?? null,
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

        // Cache results
        const cacheKey = buildCacheKey(currentQuery, currentTimeRange, currentMode);
        // We need to read the final searchResults via a callback since state may not have flushed yet
        setSearchResults(finalResults => {
          const cacheEntry: CachedSearchResult = {
            results: finalResults,
            histogramData: streamedMetadata.histogramData,
            serverFieldStats: null,
            totalCount: streamedMetadata.totalCount || data.total_rows_delivered || finalResults.length,
            executionTimeMs: streamedMetadata.executionTimeMs,
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
          const apiTime = toApiTimeRange(currentTimeRange);
          fetchFieldStats({ query: currentQuery, start: apiTime.start, end: apiTime.end })
            .then(fieldStatsResponse => {
              if (fieldStatsResponse.fields && fieldStatsResponse.fields.length > 0) {
                setServerFieldStats(fieldStatsResponse.fields);
              }
            })
            .catch(err => console.warn('Failed to fetch field stats:', err));
        }

        // Capture search in notebook
        const apiTime = toApiTimeRange(currentTimeRange);
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
          // Fall back to async polling
          api.searchAsync(request).then(asyncResponse => {
            if (asyncResponse.job_id) {
              setAsyncJobId(asyncResponse.job_id);
              queryClient.invalidateQueries({ queryKey: ['search-jobs'] });
              startAsyncJobPolling(asyncResponse.job_id, currentQuery, currentTimeRange, currentMode, isAggregate);
            } else {
              // Sync response
              processAsyncJobResult(asyncResponse as unknown as import('@/lib/api/types').SearchResponse, currentQuery, currentTimeRange, currentMode, isAggregate);
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
    });

    sseControllerRef.current = controller;
  }, [clearAsyncJob, processAsyncJobResult, startAsyncJobPolling, queryClient, fetchFieldStats, toApiTimeRange, captureSearch, requestQueryCorrection]);

  // Main search function
  const handleSearch = useCallback(async (page: number = 1, append: boolean = false, searchQuery?: string, searchMode?: 'piped' | 'sql', searchTimeRange?: TimeRangeValue, useCache?: boolean) => {
    // Use provided parameters or fall back to current state
    const currentQuery = searchQuery ?? query;
    const currentMode = searchMode ?? queryMode;
    const currentTimeRange = searchTimeRange ?? timeRange;
    
    // Check for empty query
    if (!currentQuery?.trim()) {
      setSearchError({ code: 'EMPTY_QUERY', message: 'Please enter a search query' });
      return;
    }

    // NAN-173: Block SQL execution without permission
    if (currentMode === 'sql' && !canSql) {
      setSearchError({ code: 'PERMISSION_DENIED', message: 'Raw SQL queries require the search:sql permission. Contact your administrator.' });
      return;
    }
    
    if (abortControllerRef.current) abortControllerRef.current.abort();
    abortControllerRef.current = new AbortController();
    // Generate a unique request ID for query tracking and server-side cancellation
    const requestId = crypto.randomUUID();
    currentRequestIdRef.current = requestId;
    setSearchError(null);
    setQueryReviewSuggestions([]);
    setLimitWarningDismissed(false);
    setIsSearching(true);
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
      setSearchResults([]);
      setServerFieldStats(null);
      setPeakRowsScanned(0);
      // Don't clear histogram here - keep showing previous data while loading
      // New histogram will be set when API response arrives
      setCurrentPage(1);
      // Only push to history if not restoring from back/forward navigation
      if (!isRestoringFromHistory.current) {
        updateUrl(currentQuery, currentMode, currentTimeRange, undefined, true, prevalenceMax);
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
      const apiTimeRange = toApiTimeRange(currentTimeRange);
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
          { query: cleanQuery, time_range: apiTimeRange, limit: pageSize, offset, skip_field_stats: true, table_view: true },
          currentQuery, currentTimeRange, currentMode, isAggregate
        );
        // Refresh SQL panel if visible (SSE returns early, so do it before exit)
        if (showSql) {
          explainQuery({ query: cleanQuery, timeRange: apiTimeRange }).then(
            (result) => setGeneratedSql(result.sql),
            () => {} // Silently fail - SQL display is not critical
          );
        }
        return; // Exit early - results come via SSE callbacks, streaming handles cleanup
      } else {
        // table_view: slim columns (id, timestamp, message, source_type + key UDM fields)
        // Full row data fetched on demand via fetchLog when user expands a row
        // Field stats come from separate async /api/search/field-stats endpoint
        response = await search({ query: cleanQuery, time_range: apiTimeRange, limit: pageSize, offset, use_cache: useCache, skip_field_stats: true, table_view: true, request_id: requestId });
      }

      if (abortControllerRef.current?.signal.aborted) return;

      const results: SearchResult[] = (response.results || [])
        .filter((r: unknown) => r != null && typeof r === 'object')
        .map((r: Record<string, unknown>, i: number) => ({
          id: `result-${offset + i}`,
          timestamp: parseUTCTimestamp(r?.timestamp as string),
          source: r?.source_type === 'findings'
            ? (r?.metadata as Record<string, unknown>)?.risk_entity as string || 'finding'
            : (r?.src_host as string) || (r?.src_ip as string) || 'unknown',
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
      if (effectiveTotalCount === 0) {
        // If we got exactly the limit, there's likely more data
        // Use a high estimate to enable pagination
        effectiveTotalCount = results.length >= pageSize ? results.length * 100 : results.length;
      }
      setTotalCount(effectiveTotalCount);
      setCurrentPage(page);
      if (response.generated_sql) setGeneratedSql(response.generated_sql);
      if (response.execution_time_ms !== undefined) setExecutionTimeMs(response.execution_time_ms);
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
            const fields: string[] = [];
            const event = r as unknown as Record<string, unknown>;
            if (event.src_ip) fields.push(`src_ip: ${event.src_ip}`);
            if (event.dst_ip) fields.push(`dst_ip: ${event.dst_ip}`);
            if (event.user) fields.push(`user: ${event.user}`);
            if (event.url) fields.push(`url: ${event.url}`);
            if (event.hostname) fields.push(`hostname: ${event.hostname}`);
            return fields.join(', ');
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
      
      // Store histogram data from API response (always update, even if empty)
      const histData = response.histogram && response.histogram.length > 0
        ? response.histogram.map(bucket => ({
            time: bucket.time,
            count: bucket.count
          }))
        : [];
      setHistogramData(histData);

      // Cache results for back-navigation (use local vars, not state which is async)
      const cacheKey = !append ? buildCacheKey(currentQuery, currentTimeRange, currentMode) : null;
      if (cacheKey) {
        const cacheEntry: CachedSearchResult = {
          results,
          histogramData: histData,
          serverFieldStats: null,
          totalCount: effectiveTotalCount,
          executionTimeMs: response.execution_time_ms ?? null,
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
        // Trigger async field stats fetch - don't await, let it run in background
        fetchFieldStats({ query: cleanQuery, start: apiTimeRange.start, end: apiTimeRange.end })
          .then(fieldStatsResponse => {
            if (fieldStatsResponse.fields && fieldStatsResponse.fields.length > 0) {
              setServerFieldStats(fieldStatsResponse.fields);
              // Update cache entry with field stats
              if (cacheKey) {
                const cached = searchResultCache.get(cacheKey);
                if (cached) cached.serverFieldStats = fieldStatsResponse.fields;
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
      }

      // Capture search in notebook (if active)
      if (!append) {
        const apiTime = toApiTimeRange(currentTimeRange);
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
          const result = await explainQuery({ query: cleanQuery, timeRange: apiTimeRange });
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
  }, [query, queryMode, timeRange, pageSize, search, searchSql, updateUrl, addToSearchHistory, refreshHistory, captureSearch, prevalenceMax, showSql, explainQuery, startStreamingSearch, requestQueryCorrection]);

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

  const loadMore = useCallback(() => {
    if (!isSearching && searchResults.length < totalCount) {
      handleSearch(currentPage + 1, true);
    }
  }, [isSearching, searchResults.length, totalCount, currentPage, handleSearch]);

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

    // For table/aggregate queries where we need more data, fetch from server
    if (abortControllerRef.current) abortControllerRef.current.abort();
    abortControllerRef.current = new AbortController();
    setIsSearching(true);

    try {
      const apiTimeRange = toApiTimeRange(timeRange);
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
        : await search({ query: cleanQuery, time_range: apiTimeRange, limit: effectiveSize, offset, skip_field_stats: true });

      if (abortControllerRef.current?.signal.aborted) return;

      const results: SearchResult[] = (response.results || [])
        .filter((r: unknown) => r != null && typeof r === 'object')
        .map((r: Record<string, unknown>, i: number) => ({
          id: `result-${offset + i}`,
          timestamp: parseUTCTimestamp(r?.timestamp as string),
          source: r?.source_type === 'findings'
            ? (r?.metadata as Record<string, unknown>)?.risk_entity as string || 'finding'
            : (r?.src_host as string) || (r?.src_ip as string) || 'unknown',
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
  }, [isAggregateQuery, displayType, executedQuery, searchResults.length, timeRange, tablePageSize, totalCount, queryMode, prevalenceMax, search, searchSql]);

  const handleTablePageSizeChange = useCallback((newSize: number) => {
    setTablePageSize(newSize);
    // Reset to first page and refetch with the new size — pass override so the
    // fetch doesn't use the stale state value still in handleTablePageChange's closure.
    handleTablePageChange(0, newSize);
  }, [handleTablePageChange]);

  // Fetch full log data on row expand (table_view mode)
  // Uses narrow time window around event timestamp for efficient partition pruning
  const fetchLog = useCallback(async (logId: string, eventTimestamp: Date): Promise<Record<string, unknown> | null> => {
    try {
      // Create a 2-second window around the event timestamp for efficient lookup
      // This narrows the query to a single partition instead of the full search range
      const start = new Date(eventTimestamp.getTime() - 1000);
      const end = new Date(eventTimestamp.getTime() + 1000);
      const narrowTimeRange = { start: start.toISOString(), end: end.toISOString() };
      const response = await api.fetchLog(logId, narrowTimeRange);
      if (response.event) return response.event;
      // Narrow time window missed — retry without time range constraint
      const fallback = await api.fetchLog(logId);
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
      const formattedValue = isNumeric ? value : `"${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
      const whereClause = `| where ${field} ${op} ${formattedValue}`;
      newQuery = query ? `${query} ${whereClause}` : `* ${whereClause}`;
    } else {
      // For regular fields, add to the search clause BEFORE pipe commands
      const op = exclude ? '!=' : '=';
      // Escape backslashes and quotes for the query language
      const escapedValue = value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
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
    // - _identityClause: handled separately as a raw query fragment
    const excludeFromDrilldown = new Set(['timestamp', 'bytes_out', 'bytes_in', 'bytes', 'duration', 'response_time', '_identityClause', '_tableCommand']);

    // Check for identity clause (pre-built OR expression from asset view)
    const identityClause = filters._identityClause as string | undefined;
    // Check for table command (pre-built | table from asset view drilldown)
    const tableCommand = filters._tableCommand as string | undefined;

    // Build filter clauses from the row's grouping fields
    const filterClauses = Object.entries(filters)
      .filter(([field, value]) => value !== null && value !== undefined && !excludeFromDrilldown.has(field))
      .map(([field, value]) => {
        const strValue = typeof value === 'string' ? value : String(value);
        // Escape backslashes and quotes for the query language
        const escapedValue = strValue.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
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
      if (filterClauses.length > 0) {
        if (newQuery) {
          newQuery = `${newQuery} ${filterClauses.join(' ')}`;
        } else {
          newQuery = filterClauses.join(' ');
        }
      }
    }
    
    // Append table command if present (from asset view "Search as table")
    if (tableCommand) {
      newQuery = `${newQuery} ${tableCommand}`;
    }

    // Update query and force re-search
    setQuery(newQuery);
    setQueryMode('piped');
    const isAggregate = checkIfAggregateQuery(newQuery);
    setIsAggregateQuery(isAggregate);
    if (!isAggregate) {
      setDisplayType(undefined); // Reset display type only for raw queries
    }
    setColumnOrder(undefined); // Reset column order from previous query
    setTablePage(0); // Reset pagination
    setSearchResults([]); // Clear current results
    setServerFieldStats(null); // Clear server field stats
    
    // Use a ref to track the new query and trigger search
    setTimeout(() => {
      // Manually trigger search with the new query
      const runDrilldownSearch = async () => {
        setSearchError(null);
        setIsSearching(true);
        // Don't clear histogram here - keep showing previous data while loading
        setCurrentPage(1);
        
        // Update URL and add to search history
        updateUrl(newQuery, 'piped', timeRange, undefined, true);
        addToSearchHistory({ query: newQuery, queryMode: 'piped', timeRange });
        refreshHistory();
        
        try {
          const apiTimeRange = toApiTimeRange(timeRange);
          // Strip comments from query before sending to API
          const cleanQuery = stripComments(newQuery);
          const response = await search({ query: cleanQuery, time_range: apiTimeRange, limit: pageSize, offset: 0 });
          
          const results: SearchResult[] = (response.results || [])
            .filter((r: unknown) => r != null && typeof r === 'object')
            .map((r: Record<string, unknown>, i: number) => ({
              id: `result-${i}`,
              timestamp: parseUTCTimestamp(r?.timestamp as string),
              source: r?.source_type === 'findings'
                ? (r?.metadata as Record<string, unknown>)?.risk_entity as string || 'finding'
                : (r?.src_host as string) || (r?.src_ip as string) || 'unknown',
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
  }, [query, timeRange, search, pageSize, updateUrl, addToSearchHistory, refreshHistory, captureSearch]);

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
  const apiTimeRange = useMemo(() => toApiTimeRange(timeRange), [timeRange]);

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

    // If we have histogram data from the API, use it (this is the accurate data)
    if (histogramData.length > 0) {
      // Map buckets and aggregate those with the same time label
      const labelMap = new Map<string, { timestamp: number; events: number }>();

      histogramData.forEach(bucket => {
        const time = parseUTCTimestamp(bucket.time);
        const label = formatTimelineLabel(time, spansDays, showSeconds);
        const existing = labelMap.get(label);
        
        if (existing) {
          // Aggregate events for buckets with same label
          existing.events += bucket.count;
          // Keep the earliest timestamp for this label
          existing.timestamp = Math.min(existing.timestamp, time.getTime());
        } else {
          labelMap.set(label, {
            timestamp: time.getTime(),
            events: bucket.count
          });
        }
      });
      
      // Convert map to array and sort by timestamp
      return Array.from(labelMap.entries())
        .map(([time, data]) => ({
          time,
          timestamp: data.timestamp,
          events: data.events
        }))
        .sort((a, b) => a.timestamp - b.timestamp);
    }
    
    // Fallback: build from search results (only accurate for non-paginated results)
    if (searchResults.length === 0) {
      return Array.from({ length: 24 }, (_, i) => {
        const time = new Date(Date.now() - (23 - i) * 60 * 60 * 1000);
        return { time: formatTimelineLabel(time, spansDays, showSeconds), timestamp: time.getTime(), events: 0 };
      });
    }
    if (isAggregateQuery && searchResults[0]?.fields?.time_bucket) {
      return searchResults.filter(r => r.fields?.time_bucket).map(result => {
        const timeBucket = parseUTCTimestamp(result.fields.time_bucket as string);
        const countField = Object.keys(result.fields).find(k => k.toLowerCase() === 'count' || k.toLowerCase().startsWith('count('));
        const events = countField ? Number(result.fields[countField]) || 1 : 1;
        return { time: formatTimelineLabel(timeBucket, spansDays, showSeconds), timestamp: timeBucket.getTime(), events };
      }).sort((a, b) => a.timestamp - b.timestamp);
    }
    const timeBuckets = new Map<string, { timestamp: number; events: number }>();
    searchResults.forEach(result => {
      const timeKey = formatTimelineLabel(result.timestamp, spansDays, showSeconds);
      const existing = timeBuckets.get(timeKey);
      if (existing) existing.events += 1;
      else timeBuckets.set(timeKey, { timestamp: result.timestamp.getTime(), events: 1 });
    });
    return Array.from(timeBuckets.entries()).sort((a, b) => a[1].timestamp - b[1].timestamp).map(([time, data]) => ({ time, timestamp: data.timestamp, events: data.events }));
  }, [histogramData, searchResults, isAggregateQuery, apiTimeRange, displayType]);

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

  // Field stats - prefer server-provided stats (from topK across ALL matching events)
  // Fall back to client-side stats for aggregate queries or when server stats unavailable
  const fieldStats = useMemo<FieldStat[]>(() => {
    // Prefer server-provided field stats (more accurate - computed across all matching events)
    if (serverFieldStats && serverFieldStats.length > 0) {
      return serverFieldStats.map(field => ({
        field: field.name,
        count: field.count,
        // Use cardinality if provided, otherwise count top_values
        uniqueCount: field.cardinality ?? field.top_values.length,
        topValues: field.top_values.map(([value, count]) => ({
          value,
          count,
          percentage: field.count > 0 ? Math.round((count / field.count) * 100) : 0
        }))
      }));
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
  // highlighting before the user runs their first search
  useEffect(() => {
    if (!isAuthenticated) return;
    api.getExtFieldNames()
      .then((names: string[]) => {
        if (names.length > 0) {
          registerDynamicFields(names);
        }
      })
      .catch(() => {}); // Silently fail — ext fields are optional
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

      // Small delay to ensure state is ready
      const timer = setTimeout(() => {
        handleSearch(1, false, urlQuery, queryMode, timeRange);
        // Clear the run and ai params from URL after execution
        const params = new URLSearchParams(searchParams);
        params.delete('run');
        params.delete('ai');
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
      
      const timer = setTimeout(() => handleSearch(1, false, urlQuery, queryMode, timeRange), 100);
      return () => clearTimeout(timer);
    }
  }, []);

  // Sync state from URL when browser back/forward is used
  const prevUrlRef = useRef(searchParams.toString());
  useEffect(() => {
    const currentUrlStr = searchParams.toString();
    // Only process if URL actually changed (back/forward navigation)
    if (currentUrlStr === prevUrlRef.current) return;
    prevUrlRef.current = currentUrlStr;
    
    const currentUrlQuery = searchParams.get('q') || '';
    const currentUrlMode = (searchParams.get('mode') as 'piped' | 'sql' | 'natural') || 'piped';
    const currentUrlTimePreset = searchParams.get('time') || '';
    const currentUrlTimeStart = searchParams.get('start') || '';
    const currentUrlTimeEnd = searchParams.get('end') || '';
    
    // Build time range from URL
    const urlTimeRange: TimeRangeValue = currentUrlTimeStart && currentUrlTimeEnd
      ? { type: 'custom', start: new Date(currentUrlTimeStart), end: new Date(currentUrlTimeEnd) }
      : currentUrlTimePreset
        ? { type: 'preset', preset: currentUrlTimePreset }
        : { type: 'preset', preset: 'Last hour' };
    
    // Normalize mode (convert old 'natural' to 'piped')
    const normalizedMode = currentUrlMode === 'natural' ? 'piped' : currentUrlMode as 'piped' | 'sql';
    
    // Check if this is a meaningful state change
    const queryChanged = currentUrlQuery !== query;
    const modeChanged = normalizedMode !== queryMode;
    const timeChanged = JSON.stringify(urlTimeRange) !== JSON.stringify(timeRange);
    
    // Always restore state from URL if there's a meaningful change, regardless of hasSearched
    if (queryChanged || modeChanged || timeChanged) {
      // URL changed from back/forward - restore state and re-search
      // Set flag BEFORE updating state to prevent timeRange effect from also triggering
      isRestoringFromHistory.current = true;
      
      // Update state
      setQuery(currentUrlQuery);
      setQueryMode(normalizedMode);
      setTimeRange(urlTimeRange);
      
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
      prevTimeRangeRef.current = urlTimeRange;
      
      // If there's a query in the URL, check cache first, then fall back to search
      if (currentUrlQuery.trim() && currentUrlMode !== 'natural') {
        const cacheKey = buildCacheKey(currentUrlQuery, urlTimeRange, normalizedMode);
        const cached = searchResultCache.get(cacheKey);
        if (cached && (Date.now() - cached.cachedAt) < CACHE_TTL_MS) {
          // Restore from cache — instant back-navigation
          setSearchResults(cached.results);
          setHistogramData(cached.histogramData);
          setServerFieldStats(cached.serverFieldStats);
          setTotalCount(cached.totalCount);
          setExecutionTimeMs(cached.executionTimeMs);
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
          // Cache miss or expired — re-fetch
          if (cached) searchResultCache.delete(cacheKey);
          setTimeout(() => {
            handleSearch(1, false, currentUrlQuery, normalizedMode, urlTimeRange);
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
  }, [searchParams, query, queryMode, timeRange, handleSearch]);

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
  const warningRowCount = isAggregateQuery ? peakRowsScanned : totalCount;
  const showLimitWarning =
    warningRowCount >= 1_000_000 && !isSearching && hasSearched && !limitWarningDismissed;
  const showErrorOrWarning = !!searchError || showLimitWarning;

  return (
    <div className="search-console-page flex flex-col gap-2.5 w-full min-w-0 overflow-x-hidden md:[overflow-x:clip]">
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
            <span className="text-primary search-console-mode">{queryMode === 'sql' ? 'SQL Pipeline' : 'nPL Pipeline'}</span>
            <span className="text-muted-foreground/40 hidden md:inline">›</span>
            <span className="hidden md:inline text-muted-foreground search-console-time">UTC {new Date().toLocaleTimeString('en-US', { timeZone: 'UTC', hour: '2-digit', minute: '2-digit', hour12: false })}</span>
          </div>

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
              <DateTimeRangePicker value={timeRange} onChange={setTimeRange} variant="search" />
              <Button
                className="search-console-action rounded-md h-[34px] w-[34px] p-0 border bg-primary hover:bg-primary/90 border-border text-primary-foreground transition-colors duration-300 ease-out"
                onClick={() => showAiSuggestion ? handleAskMelod(query) : handleSearch()}
                disabled={isSearching || aiLoading}
              >
                {isSearching || aiLoading ? (
                  <Loader2 className="w-[15px] h-[15px] animate-spin" />
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

          {/* AI hint popup - shows once to educate users */}
          {showAiHint && !showAiSuggestion && !aiLoading && !showAiThinking && (
            <div className="flex justify-center animate-in fade-in slide-in-from-top-2 duration-300">
              <div className="relative bg-ai text-ai-foreground px-4 py-2.5 rounded-xl shadow-lg shadow-ai-shadow">
                <div className="absolute -top-2 left-1/2 -translate-x-1/2 w-0 h-0 border-l-8 border-r-8 border-b-8 border-transparent border-b-ai" />
                <div className="flex items-center gap-2">
                  <PivtIcon className="w-4 h-4 flex-shrink-0" />
                  <p className="text-sm">
                    <span className="font-medium">Tip:</span> Try typing in natural language like "show me failed logins from yesterday"
                  </p>
                  <button
                    onClick={() => setShowAiHint(false)}
                    className="ml-2 text-ai-foreground/70 hover:text-ai-foreground flex-shrink-0"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>
              </div>
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
                  {aiLoading && <Loader2 className="w-3 h-3 animate-spin" />}
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
                    {isCreatingShortUrl ? <Loader2 className="w-[13px] h-[13px] animate-spin" /> : <Link2 className="w-[13px] h-[13px]" />}
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
              <span>{queryMode === 'sql' ? 'SQL' : 'NPL'}</span>
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
                    {explaining ? <Loader2 className="w-[13px] h-[13px] animate-spin" /> : <Code className="w-[13px] h-[13px]" />}
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
          />

          {/* Search jobs modal — opened from the More (...) menu */}
          <SearchJobsModal
            open={jobsModalOpen}
            onOpenChange={setJobsModalOpen}
            onLoadJob={(jobId) => {
              navigate(`/search?job_id=${jobId}`);
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
                      <input
                        type="checkbox"
                        checked={saveSearchShared}
                        onChange={(e) => setSaveSearchShared(e.target.checked)}
                        className="w-3.5 h-3.5 accent-primary"
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
                    {saving && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
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
          {searchError?.warningSeverity === 'info' ? (
            <Info
              className="w-4 h-4 flex-shrink-0"
              style={{ color: 'color-mix(in srgb, var(--primary) 70%, transparent)' }}
            />
          ) : (
            <AlertTriangle
              className="w-4 h-4 flex-shrink-0"
              style={{
                color: `color-mix(in srgb, ${
                  searchError?.code === 'PARSE_ERROR' || searchError?.code === 'EMPTY_QUERY' || searchError?.code === 'VALIDATION_ERROR'
                    ? 'var(--destructive)'
                    : 'var(--warning)'
                } 70%, transparent)`,
              }}
            />
          )}
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
                        <span className="text-xs text-muted-foreground/60">{aiSuggestion.description}</span>
                      </div>
                    );
                  }
                  return (
                    <>
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-xs font-semibold uppercase tracking-wide text-foreground/75">
                          {searchError.code === 'PARSE_ERROR' ? 'Syntax Error' :
                           searchError.code === 'EMPTY_QUERY' ? 'Empty Query' :
                           searchError.code === 'VALIDATION_ERROR' ? 'Query Blocked' :
                           searchError.warningSeverity === 'info' ? 'Info' :
                           'Warning'}
                        </span>
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
                          <Loader2 className="w-3 h-3 animate-spin text-violet-400" />
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
                <span className="text-amber-400 font-medium">{totalCount.toLocaleString()}+ hits</span>
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
                <Loader2 className="w-3 h-3 animate-spin text-violet-400" />
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
        {!isTreeView && displayType !== 'timechart' && displayType !== 'ranked_bar' && displayType !== 'flow' && displayType !== 'asset' && displayType !== 'cloud' && displayType !== 'lateral' && (
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
            // Asset mode renders its own visualization above and skips this
            // timeline (see the enclosing condition), so we always take the
            // "modify query and re-search" path here.
            let newQuery: string;
            if (artifactType === 'hash') {
              // Search both file_hash and process_hash since different source types use different fields
              const hashQuery = `(file_hash="${artifact}" OR process_hash="${artifact}")`;
              newQuery = query ? `${query} AND ${hashQuery}` : hashQuery;
            } else {
              // Search all domain-related fields since different sources use different fields
              // dest_host (network), query (DNS), url_domain (proxy/web)
              const domainQuery = `(dest_host="${artifact}" OR query="${artifact}" OR url_domain="${artifact}")`;
              newQuery = query ? `${query} AND ${domainQuery}` : domainQuery;
            }
            setQuery(newQuery);
            // Auto-run search after adding filter
            handleSearch(1, false, newQuery, queryMode, timeRange);
          }}
          assetContext={assetContext}
          timeWindow="24h"
          resultCount={totalCount}
          query={executedQuery}
          timeRange={apiTimeRange}
        />
        )}

        {/* Field Index collapse — now rendered as a beacon pill inside the
            Results header via SearchResults' fieldsCollapsed prop. */}

        {/* Mobile Fields button - always visible on mobile when field data available */}
        {isMobile && fieldsPanelVisible && !isTreeView && displayType !== 'timechart' && displayType !== 'ranked_bar' && displayType !== 'flow' && displayType !== 'cloud' && displayType !== 'lateral' && (
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
        {analyzeActive && hasSearched && searchResults.length > 0 && (
          <div className="flex-1 flex flex-col min-h-0 min-w-0">
            <AnalyzeView
              query={query}
              queryMode={queryMode}
              results={searchResults}
              totalCount={totalCount}
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
        {!analyzeActive && (() => {
          const showFieldsPanel = fieldsPanelVisible && !isTreeView &&
            displayType !== 'timechart' && displayType !== 'ranked_bar' && displayType !== 'flow' && displayType !== 'asset' && displayType !== 'cloud' && displayType !== 'lateral';
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
                      isExpanded={fieldsPanelExpanded}
                      onToggleExpanded={() => { userToggledFieldsPanel.current = true; setFieldsPanelExpanded(!fieldsPanelExpanded); }}
                      isLoading={fieldStatsLoading && fieldStats.length === 0}
                      isLoadingMore={fieldStatsLoading && fieldStats.length > 0}
                      query={query}
                      timeRange={apiTimeRange}
                      onFetchFieldValues={(field, q, start, end) =>
                        fetchSearchFieldValues({ field, query: q, start, end, limit: 100 })
                      }
                    />
                  </div>
                )}
              </div>

              {/* Results Area */}
              <div className="flex-1 min-w-0">
                <div className="w-full min-w-0 overflow-x-hidden md:[overflow-x:clip]">
                  <SearchResults
                    results={searchResults}
                    totalCount={totalCount}
                    isSearching={isSearching}
                    hasSearched={hasSearched}
                    isAggregateQuery={isAggregateQuery}
                    displayType={displayType}
                    histogramHasData={histogramData && histogramData.length > 0}
                    query={query}
                    executedQuery={executedQuery}
                    onAddToQuery={addToQuery}
                    onSetQuery={(newQuery) => {
                      setQuery(newQuery);
                      handleSearch(1, false, newQuery, queryMode, timeRange);
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
                    timeRange={toApiTimeRange(timeRange)}
                    melodEnabled={melodStatus?.connected || false}
                    onSummarize={() => setAnalyzeActive(true)}
                    asyncJobId={asyncJobId}
                    asyncJobStatus={asyncJobStatus}
                    asyncJobProgress={asyncJobProgress}
                    queuePosition={queuePosition}
                    estimatedWait={estimatedWait}
                    onCancelAsyncJob={handleCancelAsyncJob}
                    isStreamingResults={isStreamingResults}
                    cachedAt={cachedResultsTimestamp}
                    onRefreshCache={() => { setCachedResultsTimestamp(null); handleSearch(); }}
                    fieldsCollapsed={showFieldsPanel && !fieldsPanelExpanded}
                    fieldsCount={fieldStats.length}
                    onExpandFields={() => { userToggledFieldsPanel.current = true; setFieldsPanelExpanded(true); }}
                  />
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
            isExpanded={true}
            onToggleExpanded={() => setMobileFieldsOpen(false)}
            isLoading={fieldStatsLoading && fieldStats.length === 0}
            isLoadingMore={fieldStatsLoading && fieldStats.length > 0}
            query={query}
            timeRange={apiTimeRange}
            onFetchFieldValues={(field, q, start, end) =>
              fetchSearchFieldValues({ field, query: q, start, end, limit: 100 })
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
        isSearching={isSearching}
        hasSearched={hasSearched}
        totalCount={totalCount}
        executionTimeMs={executionTimeMs}
        asyncJobProgress={asyncJobProgress}
        asyncJobStatus={asyncJobStatus}
        queuePosition={queuePosition}
        isStreamingResults={isStreamingResults}
        onCancel={handleCancelAsyncJob}
        tailActive={tailActive}
        tailInterval={tailInterval}
      />
    </div>
  );
}
