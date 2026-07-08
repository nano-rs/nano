// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Panel Component
 * 
 * A dashboard panel that displays visualizations with loading, error, and empty states.
 * Includes a hover menu with actions (edit, duplicate, delete, view query, fullscreen)
 * and a refresh button with last refresh timestamp.
 * 
 * Requirements: 8.1, 11.1, 11.2, 11.3, 11.4, 11.5
 */

import { useEffect, useRef, useState } from 'react';
import { useInView } from '@/hooks/use-in-view';
import { Button } from '@/components/ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
  Dialog,
  DialogContent,
  DialogTitle,
  DialogDescription,
} from '@/components/ui/dialog';
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import {
  RefreshCw,
  MoreVertical,
  Pencil,
  Copy,
  Trash2,
  Code,
  Maximize2,
  CircleAlert,
  ChartColumn,
  LineChart,
  PieChart,
  Table,
  Activity,
  Hash,
  ExternalLink,
  BarChart3,
  Search,
} from 'lucide-react';
import { formatRelativeUTC } from '@/lib/date-utils';
import type { PanelConfig, VisualizationType } from '@/lib/api';
import type { TimeRangeValue } from '@/hooks/use-api';

// Panel data state interface
export interface PanelDataState {
  status: 'loading' | 'success' | 'error' | 'empty';
  data?: Record<string, unknown>[];
  error?: string;
  /**
   * NAN-712: structured error code from `ApiClientError.code`. Lets the
   * panel renderer differentiate "needs filter" (UNSCOPED_PREVALENCE) from
   * a generic failure and render an instructive empty state instead of a
   * red error banner.
   */
  errorCode?: string;
  /**
   * NAN-712: ApiClientError.details for structured errors. For
   * UNSCOPED_PREVALENCE this contains `{ wildcard_fields: ["source_host", ...] }`
   * so the panel can name the specific fields the user should narrow.
   */
  errorDetails?: unknown;
  lastRefresh?: Date;
}

// Drilldown filter interface
export interface DrilldownFilter {
  field: string;
  value: string;
  operator: '=' | '!=' | '>' | '<' | '>=' | '<=';
}

/**
 * NAN-1719 (CONTRACT 3): the payload a visualization emits on a drilldown click.
 * `filters` carries ALL group-by field/value pairs for the clicked element (never
 * just the first, and including numeric group-bys). For time-bucketed (timechart)
 * clicks, `anchorStart`/`anchorEnd` carry the clicked bucket's [start, start+span]
 * ISO window instead of a synthetic `time_bucket` filter. Panel is a thin
 * pass-through: it forwards this object unchanged to its parent (DashboardView).
 */
export interface DrilldownPayload {
  filters: { field: string; value: string }[];
  anchorStart?: string;
  anchorEnd?: string;
}

// Panel component props
export interface PanelProps {
  config: PanelConfig;
  data?: PanelDataState;
  timeRange: TimeRangeValue;
  isEditing: boolean;
  onEdit?: () => void;
  onDuplicate?: () => void;
  onDelete?: () => void;
  /** CONTRACT 3: forwarded unchanged from the visualization up to DashboardView. */
  onDrilldown?: (payload: DrilldownPayload) => void;
  /**
   * NAN-1719 (DSH8): a manual Refresh passes `true` to bypass the server cache
   * so hammering Refresh during an incident actually re-runs the query.
   */
  onRefresh: (bypassCache?: boolean) => void;
  /**
   * NAN-1183 lazy-load: fired when this panel enters/leaves the viewport so the
   * dashboard can run its query only once it scrolls into view. `scrollRoot` is
   * the dashboard's scrolling container, used as the IntersectionObserver root.
   */
  onVisibilityChange?: (panelId: string, visible: boolean) => void;
  scrollRoot?: Element | null;
  /**
   * NAN-780: true once the user has clicked Run at least once for this
   * dashboard. Until then, panels render a calm "Run query to show
   * results" idle state instead of the loading skeleton — otherwise
   * `panelData` is `undefined` on first paint and panels look like
   * they're actively loading when nothing is fetching.
   */
  hasRunOnce: boolean;
  /**
   * NAN-1719 (DSH8, CONTRACT 4): true when this panel's data came from the
   * server cache. Drives the "cached · refresh" footer affordance and suppresses
   * the misleading "Updated just now" stamp.
   */
  cached?: boolean;
  /** Age of the cached entry in seconds (DSH8). */
  cacheAgeSecs?: number;
  /**
   * NAN-1719 (DSH40, CONTRACT 4): true when the result hit the 10000-row panel
   * cap (or `totalCount` exceeds the shown row count). Drives a truncation badge
   * so a capped page isn't presented as complete.
   */
  truncated?: boolean;
  /** Total matching rows before the panel cap, for the truncation badge (DSH40). */
  totalCount?: number;
  /**
   * NAN-1719 (DSH52, CONTRACT 4): the panel query with `$variables` already
   * substituted, used for "Open in Search" so the opened search matches what the
   * panel actually ran (not raw `config.query` with unresolved `$vars`).
   */
  resolvedQuery?: string;
  /** The panel's effective absolute window, carried into "Open in Search" (DSH52). */
  effectiveTimeRange?: { start: string; end: string };
  children?: React.ReactNode;
}

// Get icon for visualization type — sized for the redesign panel header (13px)
function getVisualizationIcon(type: VisualizationType) {
  const cls = 'w-[13px] h-[13px]';
  switch (type) {
    case 'bar': return <ChartColumn className={cls} />;
    case 'line': return <LineChart className={cls} />;
    case 'area': return <Activity className={cls} />;
    case 'pie': return <PieChart className={cls} />;
    case 'table': return <Table className={cls} />;
    case 'single_value': return <Hash className={cls} />;
    case 'timeline': return <Activity className={cls} />;
    case 'obs_metric': return <Activity className={cls} />;
    default: return <ChartColumn className={cls} />;
  }
}

// Compact cache age: "12s", "4m", "1h" — mirrors the search CachedNotice style.
function formatCacheAge(ageSecs?: number): string {
  if (ageSecs == null || ageSecs < 0) return 'just now';
  if (ageSecs < 60) return `${ageSecs}s`;
  if (ageSecs < 3600) return `${Math.floor(ageSecs / 60)}m`;
  return `${Math.floor(ageSecs / 3600)}h`;
}

export function Panel({
  config,
  data,
  isEditing,
  onEdit,
  onDuplicate,
  onDelete,
  onDrilldown,
  onRefresh,
  onVisibilityChange,
  scrollRoot,
  hasRunOnce,
  cached,
  cacheAgeSecs,
  truncated,
  totalCount,
  resolvedQuery,
  effectiveTimeRange,
  children,
}: PanelProps) {
  const [showQueryDialog, setShowQueryDialog] = useState(false);
  const [showFullscreen, setShowFullscreen] = useState(false);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [isHovered, setIsHovered] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);

  // NAN-1183 lazy-load: report this panel's viewport visibility to the parent
  // loader (observer root = the dashboard's scrolling container).
  const [panelEl, setPanelEl] = useState<HTMLDivElement | null>(null);
  const inView = useInView(panelEl, { root: scrollRoot ?? null });
  const prevInView = useRef(false);
  useEffect(() => {
    // Report only real visibility transitions — skip the initial `false` and
    // re-runs caused purely by `onVisibilityChange` identity changes, which
    // would otherwise churn the parent loader (NAN-1183).
    if (prevInView.current === inView) return;
    prevInView.current = inView;
    onVisibilityChange?.(config.id, inView);
  }, [inView, config.id, onVisibilityChange]);

  const handleRefresh = async () => {
    setIsRefreshing(true);
    // DSH8: a manual refresh bypasses the server cache so it always re-runs.
    await onRefresh(true);
    // Small delay to show the animation
    setTimeout(() => setIsRefreshing(false), 500);
  };

  const handleCopyQuery = () => {
    navigator.clipboard.writeText(config.query);
  };

  const handleOpenInSearch = () => {
    // DSH52: open Search with the SUBSTITUTED query (so `$variables` are resolved
    // to what the panel actually ran) and the panel's effective absolute window,
    // rather than raw `config.query` with unresolved `$vars` and no time range.
    const params = new URLSearchParams({
      q: resolvedQuery ?? config.query,
      mode: config.queryMode,
    });
    if (effectiveTimeRange) {
      params.set('start', effectiveTimeRange.start);
      params.set('end', effectiveTimeRange.end);
    }
    window.open(`/search?${params.toString()}`, '_blank');
  };

  // DSH40: the result is capped/truncated when the backend says so, or when the
  // total match count exceeds the rows actually rendered.
  const shownRows = data?.data?.length ?? 0;
  const isTruncated = truncated === true || (totalCount != null && totalCount > shownRows);

  return (
    <>
      <div
        ref={setPanelEl}
        className="rounded-md border border-border bg-card h-full flex flex-col overflow-hidden group"
        onMouseEnter={() => setIsHovered(true)}
        onMouseLeave={() => setIsHovered(false)}
      >
        {/* Panel header (28-32px) — viz icon + title + hover actions */}
        <div className="px-3 h-[32px] shrink-0 flex items-center gap-2 border-b border-border">
          <span className="text-muted-foreground flex-shrink-0">
            {getVisualizationIcon(config.visualizationType)}
          </span>
          <span className="text-[12.5px] font-semibold text-foreground truncate">
            {config.title}
          </span>
          <div className="flex-1" />
          <div
            className={`flex items-center gap-0.5 transition-opacity ${
              isHovered || isEditing ? 'opacity-100' : 'opacity-0'
            }`}
          >
            <button
              type="button"
              onClick={handleRefresh}
              disabled={isRefreshing || data?.status === 'loading'}
              className="w-5 h-5 rounded hover:bg-foreground/[0.06] flex items-center justify-center text-muted-foreground hover:text-foreground disabled:opacity-50"
              title="Refresh"
            >
              <RefreshCw className={`w-[11px] h-[11px] ${isRefreshing ? 'animate-spin' : ''}`} />
            </button>
            <button
              type="button"
              onClick={() => setShowFullscreen(true)}
              className="w-5 h-5 rounded hover:bg-foreground/[0.06] flex items-center justify-center text-muted-foreground hover:text-foreground"
              title="Fullscreen"
            >
              <Maximize2 className="w-[11px] h-[11px]" />
            </button>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <button
                  type="button"
                  className="w-5 h-5 rounded hover:bg-foreground/[0.06] flex items-center justify-center text-muted-foreground hover:text-foreground"
                  aria-label="More actions"
                >
                  <MoreVertical className="w-[11px] h-[11px]" />
                </button>
              </DropdownMenuTrigger>
              <DropdownMenuContent
                align="end"
                className="bg-popover border-border w-44"
              >
                {isEditing && onEdit && (
                  <DropdownMenuItem onClick={onEdit} className="text-[12px] cursor-pointer">
                    <Pencil className="w-[12px] h-[12px] mr-2" />
                    Edit panel
                  </DropdownMenuItem>
                )}
                {isEditing && onDuplicate && (
                  <DropdownMenuItem onClick={onDuplicate} className="text-[12px] cursor-pointer">
                    <Copy className="w-[12px] h-[12px] mr-2" />
                    Duplicate
                  </DropdownMenuItem>
                )}
                <DropdownMenuItem
                  onClick={() => setShowQueryDialog(true)}
                  className="text-[12px] cursor-pointer"
                >
                  <Code className="w-[12px] h-[12px] mr-2" />
                  View query
                </DropdownMenuItem>
                {isEditing && onDelete && (
                  <>
                    <DropdownMenuSeparator />
                    <DropdownMenuItem
                      onClick={() => setShowDeleteConfirm(true)}
                      className="text-[12px] text-rose-400 focus:bg-rose-500/10 focus:text-rose-400 cursor-pointer"
                    >
                      <Trash2 className="w-[12px] h-[12px] mr-2" />
                      Delete
                    </DropdownMenuItem>
                  </>
                )}
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </div>

        {/* Panel content */}
        <div className="flex-1 min-h-0 p-3 overflow-hidden">
          <PanelContent
            data={data}
            config={config}
            onDrilldown={onDrilldown}
            hasRunOnce={hasRunOnce}
          >
            {children}
          </PanelContent>
        </div>

        {/* Footer — cache transparency (DSH8), updated stamp, truncation (DSH40) */}
        {(cached || data?.lastRefresh || isTruncated) && (
          <div className="px-3 h-[20px] shrink-0 border-t border-border flex items-center gap-2 text-[9.5px] font-mono uppercase tracking-[0.1em] text-muted-foreground/70">
            {cached ? (
              // DSH8: never show "Updated just now" for a cache hit — surface the
              // cache age with an explicit refresh (bypasses cache) affordance.
              <button
                type="button"
                onClick={() => onRefresh(true)}
                title="Served from cache — click to refresh from server"
                className="normal-case tracking-normal text-amber-500 dark:text-amber-400 hover:underline cursor-pointer"
              >
                cached {formatCacheAge(cacheAgeSecs)} ago · refresh
              </button>
            ) : data?.lastRefresh ? (
              <span>Updated {formatRelativeUTC(data.lastRefresh)}</span>
            ) : null}
            {isTruncated && (
              <>
                <span className="flex-1" />
                <span
                  className="normal-case tracking-normal text-amber-500 dark:text-amber-400"
                  title={
                    totalCount != null
                      ? `Showing ${shownRows.toLocaleString()} of ${totalCount.toLocaleString()} matching rows — results truncated at the panel cap`
                      : 'Results truncated at the panel row cap'
                  }
                >
                  truncated{totalCount != null ? ` · ${shownRows.toLocaleString()}/${totalCount.toLocaleString()}` : ''}
                </span>
              </>
            )}
          </div>
        )}
      </div>

      {/* View Query — right flyout */}
      <Sheet open={showQueryDialog} onOpenChange={setShowQueryDialog}>
        <SheetContent
          side="right"
          className="w-[560px] max-w-[min(560px,calc(100vw-24px))] bg-card border-border p-0 overflow-hidden flex flex-col gap-0"
        >
          <div className="px-4 py-3 pr-12 border-b border-border flex items-center gap-2 shrink-0">
            <Code className="w-[13px] h-[13px] text-primary" />
            <div className="flex-1 min-w-0">
              <div className="font-mono text-[10px] uppercase tracking-[0.14em] text-muted-foreground font-semibold">
                Panel query
              </div>
              <div className="text-[11px] text-muted-foreground mt-0.5">
                {config.queryMode === 'piped' ? 'Piped query' : 'SQL query'}
              </div>
            </div>
          </div>
          <SheetHeader className="hidden">
            <SheetTitle>Panel query</SheetTitle>
            <SheetDescription>
              {config.queryMode === 'piped' ? 'Piped query' : 'SQL query'}
            </SheetDescription>
          </SheetHeader>
          <div className="flex-1 min-h-0 overflow-y-auto p-4">
            <div className="rounded-md border border-border bg-foreground/[0.03] p-3 font-mono text-[12px] text-foreground">
              <pre className="whitespace-pre-wrap break-words leading-[1.5]">{config.query}</pre>
            </div>
          </div>
          <div className="px-4 py-3 border-t border-border flex items-center justify-end gap-2 shrink-0">
            <Button variant="ghost" size="sm" className="h-[28px]" onClick={() => setShowQueryDialog(false)}>
              Close
            </Button>
            <Button variant="outline" size="sm" className="h-[28px] gap-1.5" onClick={handleCopyQuery}>
              <Copy className="w-[12px] h-[12px]" />
              Copy query
            </Button>
            <Button size="sm" className="h-[28px] gap-1.5" onClick={handleOpenInSearch}>
              <ExternalLink className="w-[12px] h-[12px]" />
              Open in Search
            </Button>
          </div>
        </SheetContent>
      </Sheet>

      {/* Fullscreen Dialog */}
      <Dialog open={showFullscreen} onOpenChange={setShowFullscreen}>
        <DialogContent className="bg-card border-border max-w-[95vw] max-h-[95vh] w-[95vw] h-[95vh] p-0 overflow-hidden flex flex-col gap-0">
          <div className="h-[46px] shrink-0 px-4 flex items-center gap-3 border-b border-border">
            <span className="text-muted-foreground shrink-0">
              {getVisualizationIcon(config.visualizationType)}
            </span>
            <div className="flex items-baseline gap-2 min-w-0">
              <DialogTitle className="text-[13.5px] font-semibold text-foreground truncate max-w-[420px]">
                {config.title}
              </DialogTitle>
              <span className="text-[10.5px] font-mono text-muted-foreground/60">·</span>
              <DialogDescription className="text-[10.5px] font-mono text-muted-foreground">
                {config.queryMode === 'piped' ? 'piped' : 'sql'}
                {data?.lastRefresh && (
                  <span className="ml-2">· updated {formatRelativeUTC(data.lastRefresh)}</span>
                )}
              </DialogDescription>
            </div>
            <div className="flex-1" />
            <Button
              variant="outline"
              size="sm"
              className="h-[28px] gap-1.5"
              onClick={handleRefresh}
              disabled={isRefreshing || data?.status === 'loading'}
            >
              <RefreshCw className={`w-[12px] h-[12px] ${isRefreshing ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="h-[28px] gap-1.5"
              onClick={() => setShowQueryDialog(true)}
            >
              <Code className="w-[12px] h-[12px]" />
              View query
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="h-[28px] gap-1.5"
              onClick={handleOpenInSearch}
            >
              <ExternalLink className="w-[12px] h-[12px]" />
              Open in Search
            </Button>
          </div>

          <div className="flex-1 min-h-0 p-4 overflow-hidden">
            <FullscreenPanelContent
              data={data}
              config={config}
              onDrilldown={onDrilldown}
              hasRunOnce={hasRunOnce}
            >
              {children}
            </FullscreenPanelContent>
          </div>

          {data?.status === 'success' && data.data && (
            <div className="shrink-0 h-[24px] px-4 border-t border-border flex items-center gap-3 font-mono text-[10.5px] text-muted-foreground bg-card/40">
              <span className="tabular-nums">
                {isTruncated && totalCount != null
                  ? `${shownRows.toLocaleString()} of ${totalCount.toLocaleString()} rows`
                  : `${data.data.length} ${data.data.length === 1 ? 'row' : 'rows'}`}
              </span>
              {isTruncated && (
                <>
                  <span className="text-muted-foreground/50">·</span>
                  <span className="text-amber-400">truncated at panel cap</span>
                </>
              )}
              {cached && (
                <>
                  <span className="text-muted-foreground/50">·</span>
                  <button
                    type="button"
                    onClick={() => onRefresh(true)}
                    title="Served from cache — click to refresh from server"
                    className="text-amber-400 hover:underline cursor-pointer"
                  >
                    cached {formatCacheAge(cacheAgeSecs)} ago · refresh
                  </button>
                </>
              )}
              {config.timeRangeMode === 'custom' && (
                <>
                  <span className="text-muted-foreground/50">·</span>
                  <span className="text-primary">custom time range</span>
                </>
              )}
              <span className="flex-1" />
              {config.drilldownEnabled !== false && (
                <span className="text-emerald-400">click data points to drill down</span>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <ConfirmDialog
        open={showDeleteConfirm}
        onOpenChange={setShowDeleteConfirm}
        variant="danger"
        title="Delete panel?"
        description={
          <>
            Are you sure you want to delete &ldquo;
            <span className="text-foreground font-medium">{config.title}</span>&rdquo;? This action
            cannot be undone.
          </>
        }
        confirmLabel="Delete"
        onConfirm={() => {
          onDelete?.();
          setShowDeleteConfirm(false);
        }}
      />
    </>
  );
}

// Skeleton loaders for different visualization types
function BarChartSkeleton() {
  return (
    <div className="h-full flex items-end justify-around gap-2 px-4 pb-4">
      {[40, 65, 45, 80, 55, 70, 35].map((height, i) => (
        <div
          key={i}
          className="flex-1 bg-muted/50 rounded-t animate-pulse"
          style={{ height: `${height}%` }}
        />
      ))}
    </div>
  );
}

function LineChartSkeleton() {
  return (
    <div className="h-full flex flex-col justify-center px-4">
      <svg className="w-full h-3/4" viewBox="0 0 100 50" preserveAspectRatio="none">
        <path
          d="M 0 40 Q 15 35, 25 30 T 50 25 T 75 20 T 100 15"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          className="text-muted/50 animate-pulse"
        />
      </svg>
    </div>
  );
}

function PieChartSkeleton() {
  return (
    <div className="h-full flex items-center justify-center">
      <div className="w-32 h-32 rounded-full bg-muted/50 animate-pulse" />
    </div>
  );
}

function TableSkeleton() {
  return (
    <div className="h-full flex flex-col gap-2 px-2 py-2">
      <div className="h-6 bg-muted/60 rounded animate-pulse" />
      {[...Array(5)].map((_, i) => (
        <div key={i} className="h-5 bg-muted/30 rounded animate-pulse" />
      ))}
    </div>
  );
}

function SingleValueSkeleton() {
  return (
    <div className="h-full flex flex-col items-center justify-center gap-2">
      <div className="h-12 w-24 bg-muted/50 rounded animate-pulse" />
      <div className="h-4 w-16 bg-muted/30 rounded animate-pulse" />
    </div>
  );
}

function TimelineSkeleton() {
  return (
    <div className="h-full flex items-end justify-around gap-1 px-4 pb-4">
      {[...Array(24)].map((_, i) => (
        <div
          key={i}
          className="flex-1 bg-muted/40 rounded-t animate-pulse"
          style={{ height: `${20 + Math.random() * 60}%` }}
        />
      ))}
    </div>
  );
}

function getSkeletonForType(type: VisualizationType) {
  switch (type) {
    case 'bar': return <BarChartSkeleton />;
    case 'line': return <LineChartSkeleton />;
    case 'area': return <LineChartSkeleton />;
    case 'pie': return <PieChartSkeleton />;
    case 'table': return <TableSkeleton />;
    case 'single_value': return <SingleValueSkeleton />;
    case 'timeline': return <TimelineSkeleton />;
    default: return <BarChartSkeleton />;
  }
}

// Panel content component - handles loading, error, empty states
interface PanelContentProps {
  data?: PanelDataState;
  config: PanelConfig;
  onDrilldown?: (payload: DrilldownPayload) => void;
  isFullscreen?: boolean;
  hasRunOnce: boolean;
  children?: React.ReactNode;
}

function PanelContent({ data, config, hasRunOnce, children }: PanelContentProps) {
  // Pre-first-run idle state. Without this, undefined panelData falls through
  // to the skeleton path and panels look like they're actively loading when
  // nothing has fetched yet (NAN-780).
  if (!hasRunOnce && (!data || data.status === 'loading')) {
    return (
      <div className="h-full flex flex-col items-center justify-center text-center px-4 gap-2">
        <RefreshCw className="w-4 h-4 text-muted-foreground/60" />
        <p className="text-[12px] text-muted-foreground">
          Run query to show results
        </p>
      </div>
    );
  }

  // Loading state — skeleton matched to the viz type
  if (!data || data.status === 'loading') {
    return getSkeletonForType(config.visualizationType);
  }

  // NAN-712: panel uses `| prevalence` but resolved with no narrowing
  // filter. Render an instructive empty state — this isn't a failure,
  // it's "the user needs to apply a filter and click Run." Different
  // visual treatment from the generic error banner so users understand
  // it's actionable.
  if (data.status === 'error' && data.errorCode === 'UNSCOPED_PREVALENCE') {
    const wildcardFields =
      data.errorDetails &&
      typeof data.errorDetails === 'object' &&
      'wildcard_fields' in data.errorDetails &&
      Array.isArray((data.errorDetails as { wildcard_fields?: unknown }).wildcard_fields)
        ? ((data.errorDetails as { wildcard_fields: string[] }).wildcard_fields)
        : [];
    return (
      <div className="h-full flex flex-col items-center justify-center text-center px-4 gap-1.5">
        <Search className="w-5 h-5 text-amber-400 mb-0.5" />
        <p className="text-[12px] font-semibold text-foreground">Apply a filter to load this panel</p>
        <p className="text-[11px] text-muted-foreground max-w-md leading-[1.45]">
          This panel uses <span className="font-mono text-foreground">| prevalence</span> and won't
          run unscoped — that would scan every event for rarity. Set{' '}
          {wildcardFields.length > 0 ? (
            <>
              <span className="font-mono text-foreground">
                {wildcardFields.join(', ')}
              </span>{' '}
              to a specific value
            </>
          ) : (
            'at least one variable to a specific value'
          )}{' '}
          and click Run.
        </p>
      </div>
    );
  }

  // Error state
  if (data.status === 'error') {
    return (
      <div className="h-full flex flex-col items-center justify-center text-center px-3">
        <CircleAlert className="w-5 h-5 text-rose-400 mb-1.5" />
        <p className="text-[12px] font-semibold text-rose-400">Failed to load data</p>
        {data.error && (
          <p className="font-mono text-[10.5px] text-muted-foreground mt-1.5 max-w-full break-words leading-[1.45]">
            {data.error}
          </p>
        )}
      </div>
    );
  }

  // Empty state
  if (data.status === 'empty' || !data.data || data.data.length === 0) {
    return (
      <div className="h-full flex flex-col items-center justify-center text-center px-3">
        <BarChart3 className="w-5 h-5 text-muted-foreground/50 mb-1.5" />
        <p className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground/80 font-semibold">
          No panel data
        </p>
        <p className="text-[11.5px] text-foreground/80 mt-1.5">No results for the current scope.</p>
        <p className="font-mono text-[9.5px] uppercase tracking-[0.12em] text-muted-foreground/60 mt-0.5">
          Adjust time range or refine query
        </p>
      </div>
    );
  }

  return <div className="h-full">{children}</div>;
}

// Fullscreen panel content component - enhanced for larger display
interface FullscreenPanelContentProps {
  data?: PanelDataState;
  config: PanelConfig;
  onDrilldown?: (payload: DrilldownPayload) => void;
  hasRunOnce: boolean;
  children?: React.ReactNode;
}

function FullscreenPanelContent({ data, config, hasRunOnce, children }: FullscreenPanelContentProps) {
  // Pre-first-run idle state. Without this, undefined panelData falls through
  // to the skeleton path and panels look like they're actively loading when
  // nothing has fetched yet (NAN-780).
  if (!hasRunOnce && (!data || data.status === 'loading')) {
    return (
      <div className="h-full flex flex-col items-center justify-center text-center px-4 gap-2">
        <RefreshCw className="w-4 h-4 text-muted-foreground/60" />
        <p className="text-[12px] text-muted-foreground">
          Run query to show results
        </p>
      </div>
    );
  }

  // Loading state - show skeleton based on visualization type
  if (!data || data.status === 'loading') {
    return (
      <div className="h-full scale-150 origin-center">
        {getSkeletonForType(config.visualizationType)}
      </div>
    );
  }

  // NAN-712: unscoped-prevalence empty state — fullscreen variant.
  if (data.status === 'error' && data.errorCode === 'UNSCOPED_PREVALENCE') {
    const wildcardFields =
      data.errorDetails &&
      typeof data.errorDetails === 'object' &&
      'wildcard_fields' in data.errorDetails &&
      Array.isArray((data.errorDetails as { wildcard_fields?: unknown }).wildcard_fields)
        ? ((data.errorDetails as { wildcard_fields: string[] }).wildcard_fields)
        : [];
    return (
      <div className="h-full flex flex-col items-center justify-center text-center p-8 gap-2">
        <Search className="w-8 h-8 text-amber-400 mb-1.5" />
        <p className="text-[14px] font-semibold text-foreground">
          Apply a filter to load this panel
        </p>
        <p className="text-[12px] text-muted-foreground max-w-md leading-[1.5]">
          This panel uses <span className="font-mono text-foreground">| prevalence</span> and won't
          run unscoped — that would scan every event for rarity. Set{' '}
          {wildcardFields.length > 0 ? (
            <>
              <span className="font-mono text-foreground">{wildcardFields.join(', ')}</span> to a
              specific value
            </>
          ) : (
            'at least one variable to a specific value'
          )}{' '}
          and click Run.
        </p>
      </div>
    );
  }

  // Error state — larger for fullscreen
  if (data.status === 'error') {
    return (
      <div className="h-full flex flex-col items-center justify-center text-center p-8">
        <CircleAlert className="w-8 h-8 text-rose-400 mb-3" />
        <p className="text-[14px] font-semibold text-rose-400 mb-1.5">Failed to load data</p>
        {data.error && (
          <p className="font-mono text-[12px] text-muted-foreground max-w-md leading-[1.5]">{data.error}</p>
        )}
      </div>
    );
  }

  // Empty state — larger for fullscreen
  if (data.status === 'empty' || !data.data || data.data.length === 0) {
    return (
      <div className="h-full flex flex-col items-center justify-center text-center p-8">
        <BarChart3 className="w-8 h-8 text-muted-foreground/50 mb-3" />
        <p className="font-mono text-[11px] uppercase tracking-[0.12em] text-muted-foreground/80 font-semibold">
          No panel data
        </p>
        <p className="text-[13px] text-foreground/80 mt-2">No results returned for the current scope.</p>
        <p className="font-mono text-[10.5px] uppercase tracking-[0.12em] text-muted-foreground/60 mt-1">
          Adjust time range or refine query
        </p>
      </div>
    );
  }

  // Success state - render children (visualization) at full size
  return (
    <div className="h-full w-full">
      {children}
    </div>
  );
}

export default Panel;
