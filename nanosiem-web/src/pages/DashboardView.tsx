// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-521 — NOC dashboard view restyled against design-ref/noc-dash.html.
// Visual layer rebuilt to redesign density tokens; data fetching, drilldown,
// auto-refresh, edit-mode plumbing, and share/settings dialogs preserved.

import { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import { useParams, useSearchParams, useNavigate } from 'react-router-dom';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { useBreadcrumbTitle } from '@/hooks/useBreadcrumbTitle';
import { Button } from '@/components/ui/button';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { ScheduleReportDialog } from '@/components/reports/ScheduleReportDialog';
import { DateTimeRangePicker } from '@/components/ui/date-time-range-picker';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { GridLayout, Panel, VisualizationRenderer, DashboardEditor, buildSearchUrl, VariableControls, DashboardShareDialog, ObsMetricWidget, metricSeriesToRows } from '@/components/dashboard';
import type { PanelDataState, DrilldownPayload } from '@/components/dashboard/Panel';
import { substituteVariables as substituteQueryVariables } from '@/components/dashboard/variable-substitution';
import {
  ArrowLeft,
  CircleAlert,
  Clock,
  Download,
  LayoutDashboard,
  Loader2,
  MoreHorizontal,
  Pencil,
  RefreshCw,
  Settings,
  Share2,
  Shield,
} from 'lucide-react';
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';
import { useToast } from '@/hooks/use-toast';
import { useDashboard, usePanelQuery, useExportDashboard, useUpdateDashboard, toApiTimeRange, type TimeRangeValue } from '@/hooks/use-api';
import {
  DEFAULT_DASHBOARD_TIME_RANGE,
  hydrateDashboardTimeRange,
} from '@/lib/dashboard-time-range';
import { useRecentlyViewedDashboards } from '@/hooks/useRecentlyViewedDashboards';
import { useRecordActivity } from '@/hooks/useRecentActivity';
import { formatRelativeUTC } from '@/lib/date-utils';
import { cn } from '@/lib/utils';
import type { Dashboard, PanelConfig, LayoutItem, DashboardShareResult, UpdateDashboardRequest, TimeRange, SerializedTimeRange } from '@/lib/api';
import { api } from '@/lib/api';
import { isDashboardConflictError } from '@/lib/api/dashboards';

type AutoRefreshInterval = '30s' | '1m' | '5m' | '15m' | 'off';

// DSH8/DSH40/DSH52 (CONTRACT 4): the view stores a little extra per-panel metadata
// alongside PanelDataState so <Panel> can render cache/truncation transparency and
// carry the substituted query + resolved window into "Open in Search".
type ViewPanelDataState = PanelDataState & {
  cached?: boolean;
  cacheAgeSecs?: number;
  truncated?: boolean;
  totalCount?: number;
  resolvedQuery?: string;
  effectiveTimeRange?: { start: string; end: string };
  // DSH6/DSH53: the search service's column order (group-by fields first,
  // aggregates last) so VisualizationRenderer classifies label/value columns
  // deterministically and tables render in query order, not alphabetically.
  columnOrder?: string[];
};

// DSH25: resolve a panel's persisted custom range — new relative
// SerializedTimeRange (preset stays rolling) OR legacy absolute { start, end } —
// to an absolute window at query time.
function resolvePanelCustomRange(
  cr: TimeRange | SerializedTimeRange | undefined,
  fallback: TimeRange,
): TimeRange {
  if (!cr) return fallback;
  if ('type' in cr) {
    return toApiTimeRange(hydrateDashboardTimeRange(cr));
  }
  return cr;
}

// DSH27: the panel's pre-aggregation search stages — everything before the first
// top-level pipe (the aggregation command). Quote-aware so a literal '|' inside a
// quoted value isn't treated as a stage boundary. Preserves the panel's own scope
// (e.g. `source_type="firewall" error`) when drilling down.
function extractBaseQuery(resolvedQuery: string): string {
  let inQuote: string | null = null;
  for (let i = 0; i < resolvedQuery.length; i++) {
    const ch = resolvedQuery[i];
    if (inQuote) {
      if (ch === inQuote) inQuote = null;
      continue;
    }
    if (ch === '"' || ch === "'") {
      inQuote = ch;
      continue;
    }
    if (ch === '|') return resolvedQuery.slice(0, i).trim();
  }
  return resolvedQuery.trim();
}

const AUTO_REFRESH_OPTIONS: { value: AutoRefreshInterval; label: string; ms: number | null }[] = [
  { value: 'off', label: 'Off', ms: null },
  { value: '30s', label: '30 seconds', ms: 30000 },
  { value: '1m', label: '1 minute', ms: 60000 },
  { value: '5m', label: '5 minutes', ms: 300000 },
  { value: '15m', label: '15 minutes', ms: 900000 },
];

export function DashboardView() {
  const { id } = useParams();
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();
  const { toast } = useToast();
  
  const isEditMode = searchParams.get('edit') === 'true';
  
  const { data: dashboard, loading, error, refetch } = useDashboard(id);
  const { mutate: executePanelQuery } = usePanelQuery();
  const { mutate: exportDashboard } = useExportDashboard();
  const { mutate: updateDashboard, loading: updatingSettings } = useUpdateDashboard();
  const { addRecentDashboard } = useRecentlyViewedDashboards();
  const { recordView } = useRecordActivity();

  // Set page title
  useDocumentTitle(dashboard?.name || 'Dashboard', [dashboard?.id]);
  useBreadcrumbTitle(dashboard?.name);

  const [timeRange, setTimeRange] = useState<TimeRangeValue>(DEFAULT_DASHBOARD_TIME_RANGE);
  const [autoRefresh, setAutoRefresh] = useState<AutoRefreshInterval>('off');
  const [panelData, setPanelData] = useState<Map<string, ViewPanelDataState>>(new Map());
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [variableValues, setVariableValues] = useState<Record<string, string>>({});
  // DSH24: unsaved-editor-changes state, lifted from DashboardEditor so the
  // edit-mode wrapper Back button + a beforeunload guard can protect edits.
  const [editorDirty, setEditorDirty] = useState(false);
  const [showEditDiscard, setShowEditDiscard] = useState(false);
  // NAN-711: dashboards default to NOT auto-running on open. The user picks
  // variables / time range and clicks Run before any panel queries fire.
  // `hasRunOnce` flips to true on the first explicit Run; afterwards the
  // existing time-range / variable-change effects re-run panels normally.
  // Dashboards opting INTO auto-run set `layout.autoRun = true` and start
  // with `hasRunOnce = true` so panels fire on initial mount as before.
  const [hasRunOnce, setHasRunOnce] = useState(false);

  // Settings dialog state
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [settingsForm, setSettingsForm] = useState({
    name: '',
    description: '',
  });

  // Share dialog state
  const [shareDialogOpen, setShareDialogOpen] = useState(false);
  // NAN-1793: schedule this dashboard as a recurring HTML report.
  const [scheduleOpen, setScheduleOpen] = useState(false);

  const autoRefreshRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // NAN-1183 lazy-load: run panel queries on demand as panels scroll into view.
  // The dashboard body (overflow-auto) is the IntersectionObserver root.
  const [scrollRoot, setScrollRoot] = useState<HTMLElement | null>(null);
  const visiblePanelIds = useRef<Set<string>>(new Set());       // panels currently in view
  const inFlightPanels = useRef<Set<string>>(new Set());        // dedup guard
  const pendingReload = useRef<Set<string>>(new Set());         // DSH5: reload once the in-flight fetch settles
  const loadedEpoch = useRef<Map<string, number>>(new Map());   // params-epoch each panel last loaded at
  const paramsEpoch = useRef(0);                                // bumped on refresh / time-range / variable change
  const panelDataRef = useRef(panelData);                       // mirror, for the observer-failure safety net
  useEffect(() => {
    panelDataRef.current = panelData;
  }, [panelData]);
  // Live mirror of hasRunOnce so the visibility callback reads the committed
  // value, not a value captured before a queued setHasRunOnce(true) flushes.
  const hasRunOnceRef = useRef(hasRunOnce);
  useEffect(() => {
    hasRunOnceRef.current = hasRunOnce;
  }, [hasRunOnce]);

  // Track dashboard view in recently viewed list (local + server)
  useEffect(() => {
    if (id && dashboard && !isEditMode) {
      addRecentDashboard(id);
      recordView('dashboard', id, dashboard.name, {
        panel_count: dashboard.panels?.length || 0,
      });
    }
  }, [id, dashboard, isEditMode, addRecentDashboard, recordView]);

  // Seed (and re-seed after save) the toolbar time range from the saved
  // default. Skip while in edit mode because DashboardEditor owns its own
  // range state. After save: edit mode flips off AND defaultTimeRange has
  // updated, so this fires once and the toolbar matches the new default.
  useEffect(() => {
    if (!dashboard?.id) return;
    if (isEditMode) return;
    setTimeRange(hydrateDashboardTimeRange(dashboard.layout?.defaultTimeRange));
  }, [dashboard?.id, dashboard?.layout?.defaultTimeRange, isEditMode]);

  // Seed any variable defaults not already chosen, WITHOUT clobbering existing
  // user selections (DSH23: cross-dashboard resets are handled by the
  // dashboard-id effect below, not here). DSH16: guard against a malformed
  // imported layout whose `variables` isn't an array.
  useEffect(() => {
    const variables = dashboard?.layout?.variables;
    if (!Array.isArray(variables)) return;
    setVariableValues(prev => {
      let changed = false;
      const next = { ...prev };
      for (const variable of variables) {
        if (variable.defaultValue && next[variable.name] === undefined) {
          next[variable.name] = variable.defaultValue;
          changed = true;
        }
      }
      return changed ? next : prev;
    });
  }, [dashboard?.layout?.variables]);

  // Handle share - copy URL to clipboard
  const handleShare = useCallback(async () => {
    const shareUrl = `${window.location.origin}/dashboards/${id}`;
    try {
      await navigator.clipboard.writeText(shareUrl);
      toast({
        title: 'Link copied',
        description: 'Dashboard URL has been copied to clipboard',
      });
    } catch {
      toast({
        title: 'Failed to copy',
        description: 'Could not copy URL to clipboard',
        variant: 'destructive',
      });
    }
  }, [id, toast]);

  // Handle opening settings dialog
  const handleOpenSettings = useCallback(() => {
    if (!dashboard) return;
    setSettingsForm({
      name: dashboard.name,
      description: dashboard.description || '',
    });
    setSettingsOpen(true);
  }, [dashboard]);

  // Handle saving settings
  const handleSaveSettings = useCallback(async () => {
    if (!id || !dashboard) return;
    const trimmedDesc = settingsForm.description.trim();
    // CONTRACT 2 / DSH13: send explicit `null` to CLEAR the description
    // (undefined would leave it unchanged via COALESCE). DSH9: send the
    // last-seen updated_at for optimistic concurrency; a mismatch → 409. Cast
    // because the TS request type predates the clearable/concurrency fields.
    const data = {
      name: settingsForm.name.trim(),
      description: trimmedDesc === '' ? null : trimmedDesc,
      expected_updated_at: dashboard.updated_at,
    } as unknown as UpdateDashboardRequest;
    try {
      await updateDashboard({ id, data });
      toast({
        title: 'Settings saved',
        description: 'Dashboard settings have been updated',
      });
      setSettingsOpen(false);
      refetch();
    } catch (err) {
      if (isDashboardConflictError(err)) {
        toast({
          title: 'Dashboard changed on server',
          description: 'Someone else updated this dashboard. Reload to see the latest version before saving.',
          variant: 'destructive',
        });
      } else {
        toast({
          title: 'Failed to save',
          description: err instanceof Error ? err.message : 'Failed to update settings',
          variant: 'destructive',
        });
      }
    }
  }, [id, dashboard, settingsForm, updateDashboard, toast, refetch]);

  // Handle export - download dashboard as JSON
  const handleExport = useCallback(async () => {
    if (!id) return;
    try {
      const exportData = await exportDashboard(id);
      const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${dashboard?.name || 'dashboard'}-export.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      toast({
        title: 'Dashboard exported',
        description: 'Dashboard has been downloaded as JSON',
      });
    } catch (err) {
      toast({
        title: 'Export failed',
        description: err instanceof Error ? err.message : 'Failed to export dashboard',
        variant: 'destructive',
      });
    }
  }, [id, dashboard?.name, exportDashboard, toast]);

  // Substitute variables via the SHARED module (CONTRACT 5) — quote-aware, only
  // touches DEFINED names, quotes/escapes per nPL, unified empty-value semantics.
  const substituteVariables = useCallback((query: string): string => {
    const variables = dashboard?.layout?.variables;
    if (!Array.isArray(variables) || variables.length === 0) return query;

    const definedNames = variables.map(v => v.name);
    const values: Record<string, string> = {};
    for (const variable of variables) {
      values[variable.name] = variableValues[variable.name] ?? variable.defaultValue ?? '';
    }
    return substituteQueryVariables(query, values, definedNames);
  }, [dashboard?.layout?.variables, variableValues]);

  // DSH5: keep the latest time range + substitution fn in refs so a fetch that
  // resolves after a params change (or a reload triggered from an older callback
  // closure) always builds the request from CURRENT params — never a superseded
  // window. `fetchPanelData` reads these refs instead of closing over the values.
  const timeRangeRef = useRef(timeRange);
  useEffect(() => { timeRangeRef.current = timeRange; }, [timeRange]);
  const substituteVariablesRef = useRef(substituteVariables);
  useEffect(() => { substituteVariablesRef.current = substituteVariables; }, [substituteVariables]);

  // DSH46: the footer "Updated …" stamp reflects the most recent panel fetch,
  // not render time. Undefined until at least one panel has actually loaded.
  const lastUpdated = useMemo(() => {
    let latest: Date | undefined;
    for (const state of panelData.values()) {
      if (state.lastRefresh && (!latest || state.lastRefresh > latest)) {
        latest = state.lastRefresh;
      }
    }
    return latest;
  }, [panelData]);

  // Fetch data for a single panel. `bypassCache` is threaded from a manual
  // Refresh (CONTRACT 4) and sent as `bypass_cache` on the panel-query request,
  // so a user-initiated refresh skips the server-side result cache (DSH8/DSH52).
  const fetchPanelData = useCallback(async (panel: PanelConfig, bypassCache = false) => {
    // DSH5: capture the params-epoch at the START of the fetch. If it advances
    // (time-range / variable change) before the response lands, the result is
    // for a superseded window and must be discarded rather than rendered.
    const startedEpoch = paramsEpoch.current;
    const isStale = () => paramsEpoch.current !== startedEpoch;

    setPanelData(prev => {
      const newMap = new Map(prev);
      newMap.set(panel.id, { status: 'loading' });
      return newMap;
    });

    try {
      // DSH5: read the CURRENT time range from the ref (not a closure) so a
      // reload after a params change queries the current window.
      const currentApiTimeRange = toApiTimeRange(timeRangeRef.current);
      const effectiveTimeRange = panel.timeRangeMode === 'custom' && panel.customTimeRange
        ? resolvePanelCustomRange(panel.customTimeRange, currentApiTimeRange)
        : currentApiTimeRange;

      // NAN-1540: obs_metric widgets fetch from the metrics-v2 timeseries
      // endpoint (not the nPL/SQL panel-query path). Series are stashed as one
      // row per series so they ride the existing panelData Map; ObsMetricWidget
      // reconstructs them via rowsToMetricSeries.
      if (panel.visualizationType === 'obs_metric' && panel.metricConfig) {
        const mc = panel.metricConfig;
        const resp = await api.observability.queryMetricsV2({
          metric_name: mc.metric_name,
          time_range: effectiveTimeRange,
          service_name: mc.service_name,
          step_secs: mc.step_secs,
          agg: mc.agg,
          group_by: mc.group_by,
          filters: mc.filters,
        });
        if (isStale()) return; // DSH5: superseded — don't render stale-window data
        const rows = metricSeriesToRows(resp.series ?? []);
        const hasPoints = rows.some(
          r => Array.isArray(r.points) && (r.points as unknown[]).length > 0
        );
        setPanelData(prev => {
          const newMap = new Map(prev);
          newMap.set(panel.id, {
            status: hasPoints ? 'success' : 'empty',
            data: rows,
            lastRefresh: new Date(),
            effectiveTimeRange,
          });
          return newMap;
        });
        return;
      }

      // Substitute variables client-side (CONTRACT 5) with the CURRENT values
      // (via ref, so a post-change reload uses current selections).
      const substitutedQuery = substituteVariablesRef.current(panel.query);

      const response = await executePanelQuery({
        query: substitutedQuery,
        query_mode: panel.queryMode,
        time_range: effectiveTimeRange,
        bypass_cache: bypassCache,
      });
      if (isStale()) return; // DSH5: superseded — discard this response

      // DSH8/DSH40/DSH52 (CONTRACT 1/4): read cache + truncation metadata. Typed
      // via a local view so this compiles regardless of when the shared
      // PanelQueryResponse type gains these fields.
      const meta = response as typeof response & {
        cached?: boolean;
        cache_age_secs?: number;
        truncated?: boolean;
        column_order?: string[];
      };

      setPanelData(prev => {
        const newMap = new Map(prev);
        newMap.set(panel.id, {
          status: response.results.length > 0 ? 'success' : 'empty',
          data: response.results,
          // DSH52: don't stamp "Updated just now" on a cache hit — surface the
          // cache age instead (Panel renders the "cached · refresh" affordance).
          lastRefresh: meta.cached ? undefined : new Date(),
          cached: meta.cached,
          cacheAgeSecs: meta.cache_age_secs,
          truncated: meta.truncated,
          totalCount: response.total_count,
          resolvedQuery: substitutedQuery,
          effectiveTimeRange,
          columnOrder: meta.column_order,
        });
        return newMap;
      });
    } catch (err) {
      if (isStale()) return; // DSH5: superseded — don't render a stale error
      setPanelData(prev => {
        const newMap = new Map(prev);
        // NAN-712: ApiClientError carries `code` and `details`. Threading
        // them through the panel data state lets the Panel component
        // recognize structured errors (e.g. UNSCOPED_PREVALENCE) and
        // render an instructive empty state instead of a generic banner.
        const errorCode =
          err && typeof err === 'object' && 'code' in err && typeof err.code === 'string'
            ? err.code
            : undefined;
        const errorDetails =
          err && typeof err === 'object' && 'details' in err
            ? (err as { details?: unknown }).details
            : undefined;
        newMap.set(panel.id, {
          status: 'error',
          error: err instanceof Error ? err.message : 'Failed to fetch data',
          errorCode,
          errorDetails,
          lastRefresh: new Date(),
        });
        return newMap;
      });
    }
    // Reads timeRange / substituteVariables via refs (DSH5) so its identity is
    // stable across params changes; only executePanelQuery affects it.
  }, [executePanelQuery]);

  // NAN-1183: load one panel, de-duplicated against in-flight requests, stamping
  // the params-epoch it was fetched at so a later refresh/visibility check knows
  // whether it's stale. Stamps on completion (success or error) to avoid loops.
  //
  // DSH5: if a params-epoch bump arrives WHILE this panel is already in flight,
  // record a pending reload and re-run with the current params once the in-flight
  // fetch settles — so a time-range/variable change is never silently swallowed.
  const loadPanel = useCallback(async (panel: PanelConfig, bypassCache = false) => {
    if (inFlightPanels.current.has(panel.id)) {
      pendingReload.current.add(panel.id);
      return;
    }
    inFlightPanels.current.add(panel.id);
    const epoch = paramsEpoch.current;
    try {
      await fetchPanelData(panel, bypassCache);
    } finally {
      inFlightPanels.current.delete(panel.id);
      loadedEpoch.current.set(panel.id, epoch);
      // Re-run if params advanced during the fetch, or a reload was requested
      // while this one was in flight (DSH5). Only while still on-screen.
      const superseded = pendingReload.current.delete(panel.id) || epoch !== paramsEpoch.current;
      if (superseded && visiblePanelIds.current.has(panel.id)) {
        void loadPanel(panel, bypassCache);
      }
    }
  }, [fetchPanelData]);

  // Refresh panels with batched loading (limits concurrency under the backend
  // per-user admission cap). NAN-1183: lazy — only (re)loads panels currently in
  // view; off-screen panels load on demand when scrolled to. Bumps the epoch so
  // off-screen panels re-fetch with current params next time they become visible.
  const refreshAllPanels = useCallback(async () => {
    if (!dashboard?.panels || dashboard.panels.length === 0) return;

    const CONCURRENCY_LIMIT = 4;

    const targets = sortPanelsByLayout(dashboard.panels, dashboard.layout.items)
      .filter(panel => visiblePanelIds.current.has(panel.id));
    if (targets.length === 0) return; // nothing visible yet — observers drive the initial load

    // Bump the epoch only once we know we're reloading something, so off-screen
    // panels aren't marked stale by a refresh that loaded nothing.
    paramsEpoch.current += 1;
    setIsRefreshing(true);
    for (let i = 0; i < targets.length; i += CONCURRENCY_LIMIT) {
      // Wrap so Array.map's index arg isn't passed as loadPanel's bypassCache.
      await Promise.all(targets.slice(i, i + CONCURRENCY_LIMIT).map(panel => loadPanel(panel)));
    }
    setIsRefreshing(false);
  }, [dashboard?.panels, dashboard?.layout.items, loadPanel]);

  // NAN-711: only opt into the initial auto-fetch when the dashboard's layout
  // explicitly sets autoRun=true. Otherwise the user has to click Run, which
  // flips `hasRunOnce` to true for subsequent time-range / variable updates.
  //
  // Always reset `hasRunOnce` based on the current dashboard's autoRun flag so
  // navigating between dashboards within the same DashboardView instance
  // (e.g. via an in-app dashboard switcher that doesn't trigger a route
  // unmount) doesn't carry "I already ran" state from the previous dashboard
  // into a fresh one.
  useEffect(() => {
    if (isEditMode) return;
    // DSH23: reset variable selections to THIS dashboard's defaults when the
    // dashboard changes in place — otherwise the previous dashboard's selections
    // (e.g. host=web1) silently filter the new dashboard's panels.
    const variables = dashboard?.layout?.variables;
    const defaults: Record<string, string> = {};
    if (Array.isArray(variables)) {
      for (const variable of variables) {
        if (variable.defaultValue) defaults[variable.name] = variable.defaultValue;
      }
    }
    setVariableValues(defaults);

    if (!dashboard?.panels) return;
    // NAN-1183: reset lazy-load tracking when switching dashboards in place
    // (same component instance, new id) so stale visibility / epoch state from
    // the previous dashboard can't suppress or stale-gate the new one's panels.
    visiblePanelIds.current.clear();
    inFlightPanels.current.clear();
    pendingReload.current.clear();
    loadedEpoch.current.clear();
    paramsEpoch.current = 0;
    const shouldAutoRun = dashboard?.layout?.autoRun === true;
    setHasRunOnce(shouldAutoRun);
    if (shouldAutoRun) {
      refreshAllPanels();
    }
  }, [dashboard?.id, isEditMode]);

  // Refresh when time range or variables change — but only AFTER the user has
  // already triggered an initial run (or autoRun is on). Without this guard,
  // hydrating the time range or seeding variable defaults would fire panels
  // before the user clicks Run, defeating NAN-711.
  useEffect(() => {
    if (!hasRunOnce) return;
    if (dashboard?.panels && dashboard.panels.length > 0 && !isEditMode) {
      refreshAllPanels();
    }
  }, [timeRange, substituteVariables, isEditMode, hasRunOnce]);

  // Auto-refresh setup
  useEffect(() => {
    if (autoRefreshRef.current) {
      clearInterval(autoRefreshRef.current);
      autoRefreshRef.current = null;
    }

    if (isEditMode) return; // Don't auto-refresh in edit mode

    // NAN-711: auto-refresh ticks should not fire panels until the user has
    // run the dashboard at least once. Otherwise enabling 30s auto-refresh on
    // a freshly-opened dashboard would defeat the no-auto-run default.
    if (!hasRunOnce) return;

    const option = AUTO_REFRESH_OPTIONS.find(o => o.value === autoRefresh);
    if (!option?.ms) return;

    autoRefreshRef.current = setInterval(() => {
      // DSH50: don't fire full panel-query batches in a hidden/background tab —
      // it burns per-user admission slots and triggers 429 retries that slow the
      // active tab. Ticks resume on the visibilitychange handler below.
      if (document.hidden) return;
      refreshAllPanels();
    }, option.ms);

    // DSH50: on returning to a visible tab, refresh once so data isn't stale
    // after several skipped background ticks.
    const onVisibility = () => {
      if (!document.hidden) refreshAllPanels();
    };
    document.addEventListener('visibilitychange', onVisibility);

    return () => {
      if (autoRefreshRef.current) {
        clearInterval(autoRefreshRef.current);
      }
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, [autoRefresh, refreshAllPanels, isEditMode, hasRunOnce]);

  // NAN-1183: a panel entered/left the viewport. On enter, load it if the user
  // has run the dashboard and it isn't already current for this params-epoch.
  const onPanelVisibilityChange = useCallback((panelId: string, visible: boolean) => {
    if (!visible) {
      visiblePanelIds.current.delete(panelId);
      return;
    }
    visiblePanelIds.current.add(panelId);
    if (!hasRunOnceRef.current) return;
    if (loadedEpoch.current.get(panelId) === paramsEpoch.current) return;
    const panel = dashboard?.panels.find(p => p.id === panelId);
    if (panel) void loadPanel(panel);
  }, [dashboard?.panels, loadPanel]);

  // NAN-1183 safety net: if the IntersectionObserver never reports any panel
  // visible (e.g. an unexpected scroll-root), fall back to eager batched loading
  // so the dashboard still populates — worst case behaves like the pre-lazy path.
  useEffect(() => {
    if (!hasRunOnce || isEditMode || !dashboard?.panels?.length) return;
    const timer = setTimeout(() => {
      // Only fall back if nothing is loaded or in flight — i.e. the observer
      // genuinely never fired. Off-screen panels staying lazy is intended.
      if (panelDataRef.current.size > 0 || inFlightPanels.current.size > 0) return;
      const sorted = sortPanelsByLayout(dashboard.panels, dashboard.layout.items);
      void (async () => {
        for (let i = 0; i < sorted.length; i += 4) {
          await Promise.all(sorted.slice(i, i + 4).map(panel => loadPanel(panel)));
        }
      })();
    }, 1500);
    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hasRunOnce, isEditMode, dashboard?.id]);

  // DSH24: warn on browser close / refresh while the editor has unsaved changes.
  // (The app uses BrowserRouter, so useBlocker isn't available for SPA nav —
  // the edit-mode Back button routes through handleEditBack's confirm instead.)
  useEffect(() => {
    if (!isEditMode || !editorDirty) return;
    const handler = (e: BeforeUnloadEvent) => {
      e.preventDefault();
      e.returnValue = '';
    };
    window.addEventListener('beforeunload', handler);
    return () => window.removeEventListener('beforeunload', handler);
  }, [isEditMode, editorDirty]);

  // Handle edit mode toggle
  const handleEnterEditMode = useCallback(() => {
    setSearchParams({ edit: 'true' });
  }, [setSearchParams]);

  const handleExitEditMode = useCallback(() => {
    setEditorDirty(false);
    setSearchParams({});
    refetch(); // Refresh dashboard data after editing
  }, [setSearchParams, refetch]);

  const handleSaveComplete = useCallback(() => {
    setEditorDirty(false);
    setSearchParams({});
    refetch();
  }, [setSearchParams, refetch]);

  // DSH24: the edit-mode wrapper Back button routes through here so unsaved
  // edits prompt a confirm instead of being discarded by navigate(-1).
  const handleEditBack = useCallback(() => {
    if (editorDirty) {
      setShowEditDiscard(true);
    } else {
      navigate(-1);
    }
  }, [editorDirty, navigate]);

  // Handle drilldown navigation → Search. DSH26/DSH27 (CONTRACT 3): carry the
  // panel's pre-aggregation scope as baseQuery, ALL clicked group-by filters, an
  // anchored absolute window (the clicked bucket for timecharts, else the panel's
  // effective window), and the panel's custom drilldown template if set.
  const handleDrilldown = useCallback((panel: PanelConfig, payload: DrilldownPayload) => {
    const baseQuery =
      panel.queryMode === 'piped' ? extractBaseQuery(substituteVariables(panel.query)) : undefined;

    const effectiveAbs = panel.timeRangeMode === 'custom' && panel.customTimeRange
      ? resolvePanelCustomRange(panel.customTimeRange, toApiTimeRange(timeRange))
      : toApiTimeRange(timeRange);

    const startTime = payload.anchorStart ?? effectiveAbs.start;
    const endTime = payload.anchorEnd ?? effectiveAbs.end;

    const searchUrl = buildSearchUrl(payload.filters, {
      baseQuery,
      startTime,
      endTime,
      template: panel.drilldownTemplate,
    });
    navigate(searchUrl);
  }, [navigate, timeRange, substituteVariables]);

  if (loading) {
    return (
      <div className="p-8 flex items-center justify-center min-h-[400px]">
        <Loader2 className="w-6 h-6 animate-spin text-primary" />
      </div>
    );
  }

  if (error || !dashboard) {
    return (
      <div className="p-4">
        <div className="rounded-md border border-rose-500/30 bg-rose-500/10 p-4">
          <div className="flex items-center gap-2.5">
            <CircleAlert className="w-[14px] h-[14px] text-rose-400" />
            <p className="text-[12.5px] text-rose-400">
              {error?.message || 'Dashboard not found'}
            </p>
          </div>
          <Button
            size="sm"
            className="h-[28px] mt-3"
            onClick={() => navigate('/dashboards')}
          >
            Back to Dashboards
          </Button>
        </div>
      </div>
    );
  }

  // Edit mode — DashboardEditor still owns its own chrome; just wrap with a
  // back button at redesign density.
  if (isEditMode) {
    return (
      <div className="p-4">
        <div className="mb-3">
          <Button
            variant="ghost"
            size="sm"
            className="h-[26px] text-muted-foreground hover:text-primary"
            onClick={handleEditBack}
          >
            <ArrowLeft className="w-[12px] h-[12px]" />
            Back
          </Button>
        </div>
        <DashboardEditor
          dashboard={dashboard}
          onSave={handleSaveComplete}
          onCancel={handleExitEditMode}
          initialEditMode={true}
          onDirtyChange={setEditorDirty}
        />
        {/* DSH24: discard-confirm for the wrapper Back button while dirty. */}
        <ConfirmDialog
          open={showEditDiscard}
          onOpenChange={setShowEditDiscard}
          variant="danger"
          title="Discard changes?"
          description="You have unsaved changes to this dashboard. Leaving now will discard them."
          confirmLabel="Discard changes"
          cancelLabel="Keep editing"
          onConfirm={() => {
            setShowEditDiscard(false);
            setEditorDirty(false);
            navigate(-1);
          }}
        />
      </div>
    );
  }

  // View mode — NOC layout per design-ref/noc-dash.html (header → toolbar → grid)
  return (
    <div className="flex-1 min-h-0 flex flex-col overflow-hidden">
      {/* Board header (46px) — back, name + folder + panel count + live, share/edit */}
      <div className="h-[46px] shrink-0 border-b border-border px-4 flex items-center gap-3 bg-card/40">
        <button
          type="button"
          onClick={() => navigate(-1)}
          className="w-[22px] h-[22px] rounded-md flex items-center justify-center text-muted-foreground hover:text-foreground hover:bg-foreground/[0.05]"
          aria-label="Back to dashboards"
        >
          <ArrowLeft className="w-[13px] h-[13px]" />
        </button>
        <div className="flex items-baseline gap-2 min-w-0">
          <span className="text-[13.5px] font-semibold text-foreground truncate max-w-[400px]">
            {dashboard.name}
          </span>
          <span className="text-[10.5px] font-mono text-muted-foreground/60">·</span>
          <span className="text-[10.5px] font-mono text-muted-foreground tabular-nums">
            {dashboard.panels.length} {dashboard.panels.length === 1 ? 'panel' : 'panels'}
          </span>
          {autoRefresh !== 'off' && (
            <>
              <span className="text-[10.5px] font-mono text-muted-foreground/60">·</span>
              <span className="text-[10.5px] font-mono text-emerald-500 flex items-center gap-1">
                <span className="w-[5px] h-[5px] rounded-full bg-emerald-500 animate-pulse" />
                live · {AUTO_REFRESH_OPTIONS.find(o => o.value === autoRefresh)?.label}
              </span>
            </>
          )}
        </div>

        <span className="flex-1" />

        <div className="[&_button]:h-[28px] [&_button]:text-[12px]">
          <DateTimeRangePicker value={timeRange} onChange={setTimeRange} />
        </div>

        <Select
          value={autoRefresh}
          onValueChange={v => setAutoRefresh(v as AutoRefreshInterval)}
        >
          <SelectTrigger className="h-[28px] w-[124px] text-[12px] gap-1.5">
            <Clock className="w-[12px] h-[12px] text-muted-foreground" />
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {AUTO_REFRESH_OPTIONS.map(option => (
              <SelectItem key={option.value} value={option.value} className="text-[12px]">
                {option.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        {/* NAN-711: pre-first-run, this is the prominent "Run" button — */}
        {/* dashboards open empty until the user explicitly fires it. */}
        {/* After the first run, falls back to the standard Refresh affordance. */}
        <Button
          variant={hasRunOnce ? 'outline' : 'default'}
          size="sm"
          className="h-[28px] gap-1.5"
          onClick={() => {
            setHasRunOnce(true);
            refreshAllPanels();
          }}
          disabled={isRefreshing}
        >
          <RefreshCw className={cn('w-[12px] h-[12px]', isRefreshing && 'animate-spin')} />
          {hasRunOnce ? 'Refresh' : 'Run'}
        </Button>

        <Button variant="outline" size="sm" className="h-[28px] gap-1.5" onClick={handleShare}>
          <Share2 className="w-[12px] h-[12px]" />
          Share
        </Button>

        <Button variant="outline" size="sm" className="h-[28px] gap-1.5" onClick={handleEnterEditMode}>
          <Pencil className="w-[12px] h-[12px]" />
          Edit
        </Button>

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="outline"
              size="sm"
              className="h-[28px] w-[28px] p-0"
              aria-label="More actions"
            >
              <MoreHorizontal className="w-[14px] h-[14px]" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="bg-popover border-border">
            <DropdownMenuItem
              onClick={handleOpenSettings}
              className="text-[12px] cursor-pointer"
            >
              <Settings className="w-[12px] h-[12px] mr-2" />
              Settings
            </DropdownMenuItem>
            {dashboard.is_owner && (
              <DropdownMenuItem
                onClick={() => setShareDialogOpen(true)}
                className="text-[12px] cursor-pointer"
              >
                <Shield className="w-[12px] h-[12px] mr-2" />
                Permissions
              </DropdownMenuItem>
            )}
            <DropdownMenuItem
              onClick={handleExport}
              className="text-[12px] cursor-pointer"
            >
              <Download className="w-[12px] h-[12px] mr-2" />
              Export as JSON
            </DropdownMenuItem>
            <DropdownMenuItem
              onClick={() => setScheduleOpen(true)}
              className="text-[12px] cursor-pointer"
            >
              <Clock className="w-[12px] h-[12px] mr-2" />
              Schedule report
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              onClick={handleEnterEditMode}
              className="text-[12px] cursor-pointer"
            >
              <Pencil className="w-[12px] h-[12px] mr-2" />
              Edit dashboard
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>

      {/* Variable strip — only when variables exist (DSH16: guard a malformed import) */}
      {Array.isArray(dashboard.layout.variables) && dashboard.layout.variables.length > 0 && (
        <div className="shrink-0 border-b border-border bg-card/30 px-4 py-2">
          <VariableControls
            variables={dashboard.layout.variables}
            values={variableValues}
            onChange={(next) => {
              setVariableValues(next);
              if (!hasRunOnce) setHasRunOnce(true);
            }}
            timeRange={toApiTimeRange(timeRange)}
            hasRunOnce={hasRunOnce}
          />
        </div>
      )}

      {/* Body — grid of panels (or empty state). ref = IntersectionObserver root for lazy panel loading (NAN-1183). */}
      <div ref={setScrollRoot} className="flex-1 min-h-0 overflow-auto">
        {dashboard.panels.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center gap-3 p-10 text-center">
            <LayoutDashboard className="w-10 h-10 text-muted-foreground/40" />
            <div className="text-[13px] font-medium text-foreground">No panels yet</div>
            <div className="text-[11.5px] text-muted-foreground">
              Edit this dashboard to add panels.
            </div>
            <Button size="sm" className="h-[28px] mt-1" onClick={handleEnterEditMode}>
              <Pencil className="w-[12px] h-[12px]" />
              Edit dashboard
            </Button>
          </div>
        ) : (
          <div className="p-2">
            {/* NAN-711: pre-first-run banner. Renders above the grid until the */}
            {/* user clicks Run, then disappears. Tells the user why every */}
            {/* panel is empty without making them squint at the toolbar to */}
            {/* find the highlighted Run button. */}
            {!hasRunOnce && (
              <div className="mb-3 px-3 py-2.5 rounded-md border border-border bg-foreground/[0.02] flex items-center gap-2.5">
                <RefreshCw className="w-[12px] h-[12px] text-muted-foreground" />
                <span className="text-[12px] text-muted-foreground">
                  Set your variables and click{' '}
                  <span className="font-mono text-foreground">Run</span> to load
                  panel data.
                </span>
              </div>
            )}
            <DashboardGrid
              dashboard={dashboard}
              panelData={panelData}
              onRefreshPanel={loadPanel}
              onPanelVisibilityChange={onPanelVisibilityChange}
              scrollRoot={scrollRoot}
              timeRange={timeRange}
              onDrilldown={handleDrilldown}
              hasRunOnce={hasRunOnce}
            />
          </div>
        )}
      </div>

      {/* Status bar — small mono footer with last-updated stamp */}
      <div className="shrink-0 h-[24px] border-t border-border px-4 flex items-center gap-3 font-mono text-[10px] text-muted-foreground/70 bg-card/40">
        <span className="tabular-nums">
          {dashboard.panels.length} {dashboard.panels.length === 1 ? 'panel' : 'panels'}
        </span>
        {lastUpdated && (
          <>
            <span className="text-muted-foreground/50">·</span>
            <span>Updated {formatRelativeUTC(lastUpdated)}</span>
          </>
        )}
        <span className="flex-1" />
        {dashboard.description && (
          <span className="truncate max-w-[60%] text-muted-foreground/60">{dashboard.description}</span>
        )}
      </div>

      {/* Settings — right flyout */}
      <Sheet open={settingsOpen} onOpenChange={setSettingsOpen}>
        <SheetContent
          side="right"
          className="w-[480px] max-w-[min(480px,calc(100vw-24px))] bg-card border-border p-0 overflow-hidden flex flex-col gap-0"
        >
          <div className="px-4 py-3 pr-12 border-b border-border flex items-center gap-2 shrink-0">
            <Settings className="w-[13px] h-[13px] text-primary" />
            <div className="flex-1 min-w-0">
              <div className="font-mono text-[10px] uppercase tracking-[0.14em] text-muted-foreground font-semibold">
                Dashboard settings
              </div>
              <div className="text-[11px] text-muted-foreground mt-0.5">
                Update the name and description.
              </div>
            </div>
          </div>
          <SheetHeader className="hidden">
            <SheetTitle>Dashboard settings</SheetTitle>
            <SheetDescription>Update the dashboard name and description.</SheetDescription>
          </SheetHeader>
          <div className="flex-1 min-h-0 overflow-y-auto p-4 flex flex-col gap-3">
            <div className="flex flex-col gap-1.5">
              <label className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
                Name
              </label>
              <Input
                value={settingsForm.name}
                onChange={e => setSettingsForm({ ...settingsForm, name: e.target.value })}
                placeholder="Dashboard name"
                className="h-[30px] text-[12.5px]"
              />
            </div>
            <div className="flex flex-col gap-1.5">
              <label className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
                Description (optional)
              </label>
              <Textarea
                value={settingsForm.description}
                onChange={e => setSettingsForm({ ...settingsForm, description: e.target.value })}
                placeholder="Describe this dashboard…"
                className="text-[12px] resize-none"
                rows={3}
              />
            </div>
          </div>
          <div className="px-4 py-3 border-t border-border flex items-center justify-end gap-2 shrink-0">
            <Button variant="ghost" size="sm" className="h-[28px]" onClick={() => setSettingsOpen(false)}>
              Cancel
            </Button>
            <Button
              size="sm"
              className="h-[28px] gap-1.5"
              onClick={handleSaveSettings}
              disabled={updatingSettings || !settingsForm.name.trim()}
            >
              {updatingSettings && <Loader2 className="w-[12px] h-[12px] animate-spin" />}
              Save
            </Button>
          </div>
        </SheetContent>
      </Sheet>

      {/* Share Dialog (component owns its own visuals; left as-is for now) */}
      <DashboardShareDialog
        open={shareDialogOpen}
        onOpenChange={setShareDialogOpen}
        dashboardId={dashboard.id}
        dashboardName={dashboard.name}
        currentVisibility={dashboard.visibility || 'public'}
        currentSharedGroups={dashboard.shared_groups || []}
        isOwner={dashboard.is_owner ?? false}
        onShare={(result: DashboardShareResult) => {
          refetch();
          toast({
            title: 'Permissions updated',
            description: `Dashboard visibility set to ${result.dashboard.visibility}`,
          });
        }}
      />

      {/* Schedule report (NAN-1793) — cron this dashboard into an HTML artifact */}
      <ScheduleReportDialog
        open={scheduleOpen}
        onOpenChange={setScheduleOpen}
        preset={{
          source_type: 'dashboard',
          source_dashboard_id: dashboard.id,
          dashboard_name: dashboard.name,
          defaultName: `${dashboard.name} report`,
        }}
      />
    </div>
  );
}

// Sort panels top-to-bottom (then left-to-right) by grid layout position, so
// "above the fold" panels load first. DSH16: tolerate a malformed imported
// layout whose `items` isn't an array instead of throwing on `.find`.
function sortPanelsByLayout(panels: PanelConfig[], layoutItems: LayoutItem[]): PanelConfig[] {
  const items = Array.isArray(layoutItems) ? layoutItems : [];
  const list = Array.isArray(panels) ? panels : [];
  return [...list].sort((a, b) => {
    const aLayout = items.find(l => l.i === a.id);
    const bLayout = items.find(l => l.i === b.id);
    const aY = aLayout?.y ?? Infinity;
    const bY = bLayout?.y ?? Infinity;
    if (aY === bY) return (aLayout?.x ?? 0) - (bLayout?.x ?? 0);
    return aY - bY;
  });
}

interface DashboardGridProps {
  dashboard: Dashboard;
  panelData: Map<string, ViewPanelDataState>;
  onRefreshPanel: (panel: PanelConfig, bypassCache?: boolean) => void;
  onPanelVisibilityChange?: (panelId: string, visible: boolean) => void;
  scrollRoot?: Element | null;
  timeRange: TimeRangeValue;
  isEditing?: boolean;
  onLayoutChange?: (layout: LayoutItem[]) => void;
  onDrilldown?: (panel: PanelConfig, payload: DrilldownPayload) => void;
  hasRunOnce?: boolean;
}

function DashboardGrid({
  dashboard,
  panelData,
  onRefreshPanel,
  onPanelVisibilityChange,
  scrollRoot,
  timeRange,
  isEditing = false,
  onLayoutChange,
  onDrilldown,
  hasRunOnce = false,
}: DashboardGridProps) {
  const { layout, panels } = dashboard;

  // Handle layout changes (only in edit mode)
  const handleLayoutChange = useCallback((newLayout: LayoutItem[]) => {
    if (onLayoutChange) {
      onLayoutChange(newLayout);
    }
  }, [onLayoutChange]);

  // Render function for each panel
  const renderPanel = useCallback((panel: PanelConfig) => {
    const data = panelData.get(panel.id);

    // Check if drilldown is enabled for this panel (default to true if not specified)
    const drilldownEnabled = panel.drilldownEnabled !== false;
    // CONTRACT 3: bind the panel into the drilldown callback so DashboardView can
    // derive baseQuery / template / anchored window from it.
    const drilldownHandler =
      drilldownEnabled && onDrilldown
        ? (payload: DrilldownPayload) => onDrilldown(panel, payload)
        : undefined;

    return (
      <Panel
        config={panel}
        data={data}
        timeRange={timeRange}
        isEditing={isEditing}
        onRefresh={(bypassCache) => onRefreshPanel(panel, bypassCache)}
        onVisibilityChange={onPanelVisibilityChange}
        scrollRoot={scrollRoot}
        onDrilldown={drilldownHandler}
        hasRunOnce={hasRunOnce}
        cached={data?.cached}
        cacheAgeSecs={data?.cacheAgeSecs}
        truncated={data?.truncated}
        totalCount={data?.totalCount}
        resolvedQuery={data?.resolvedQuery}
        effectiveTimeRange={data?.effectiveTimeRange}
      >
        {data?.status === 'success' && data.data && (
          panel.visualizationType === 'obs_metric' && panel.metricConfig ? (
            <ObsMetricWidget config={panel.metricConfig} data={data.data} />
          ) : (
            <VisualizationRenderer
              type={panel.visualizationType}
              config={panel.visualizationConfig}
              data={data.data}
              columnOrder={data.columnOrder}
              onDrilldown={drilldownHandler}
            />
          )
        )}
      </Panel>
    );
  }, [panelData, onRefreshPanel, onPanelVisibilityChange, scrollRoot, timeRange, isEditing, onDrilldown, hasRunOnce]);

  return (
    <GridLayout
      panels={panels}
      layoutItems={layout.items}
      isEditing={isEditing}
      onLayoutChange={handleLayoutChange}
      renderPanel={renderPanel}
      columns={layout.columns}
      rowHeight={layout.rowHeight}
    />
  );
}
