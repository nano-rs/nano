// SPDX-License-Identifier: AGPL-3.0-or-later

import { TelemetrySetupHint } from '@/components/observability/TelemetryUnavailable';

/**
 * MetricsExplorer (NAN-1540)
 *
 * The metrics-v2 query builder + viz. One query at a time, built from:
 *   metric (listMetricNames) · aggregation (avg/sum/min/max/count/rate/p50/p95/
 *   p99) · group-by (a tag key via the tags endpoint) · tag filters (key=value
 *   via the tags endpoint), with a viz switcher over the returned series[].
 *
 * Fetches via api.observability.queryMetricsV2 (multi-series) and discovers tag
 * keys/values via api.observability.listMetricTags. "Add to dashboard" persists
 * the query as an obs_metric widget; "Create monitor" opens the monitor dialog
 * prefilled from the query.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertCircle,
  BarChart3,
  ChevronDown,
  Grid3x3,
  Hash,
  LayoutDashboard,
  LineChart,
  ListOrdered,
  Plus,
  RotateCw,
  Sigma,
  X,
} from 'lucide-react';
import { LoadingIcon } from '@/components/icons/LoadingIcon';

import { api } from '@/lib/api';
import type { CacheMeta } from '@/lib/api';
import { CachedNotice } from '@/components/search/CachedNotice';
import { useReportPhase2Status } from '@/components/search/footer-reporter';
import { useIsLiveRun } from '@/components/search/live-run-context';
import { cn } from '@/lib/utils';
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
} from '@/components/ui/dropdown-menu';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import type {
  MetricAgg,
  MetricFilter,
  MetricSeries,
  MetricWidgetConfig,
  MetricWidgetViz,
  TimeRange,
} from '@/lib/api/types';
import { MetricViz, type MetricVizMode } from './MetricViz';
import { MetricMonitorDialog } from './MetricMonitorDialog';
import { AddMetricToDashboardDialog } from './AddMetricToDashboardDialog';
import { seriesColor } from '@/lib/chart-colors';

const AGG_OPTS: MetricAgg[] = [
  'avg',
  'sum',
  'min',
  'max',
  'count',
  'rate',
  'p50',
  'p95',
  'p99',
];

const NO_GROUP = '__none__';

const VIZ_OPTS: Array<{ mode: MetricVizMode; label: string; icon: typeof LineChart }> = [
  { mode: 'timeseries', label: 'Line', icon: LineChart },
  { mode: 'area', label: 'Area', icon: LineChart },
  { mode: 'toplist', label: 'Top list', icon: ListOrdered },
  { mode: 'query_value', label: 'Value', icon: Hash },
  { mode: 'distribution', label: 'Distribution', icon: BarChart3 },
  { mode: 'heatmap', label: 'Heatmap', icon: Grid3x3 },
];

const STEP_OPTS: Array<[label: string, secs: number]> = [
  ['30s', 30],
  ['1m', 60],
  ['5m', 300],
  ['15m', 900],
  ['1h', 3600],
];

/** Map the explorer's richer viz modes down to the dashboard widget's 3 modes. */
function vizToWidgetViz(mode: MetricVizMode): MetricWidgetViz {
  if (mode === 'toplist' || mode === 'distribution' || mode === 'heatmap') return 'toplist';
  if (mode === 'query_value') return 'query_value';
  return 'timeseries';
}

/**
 * Where the metric-name catalog stands (NAN-4098). The picker always accepts a
 * typed metric name, so a slow or failed catalog never leaves it unusable, and
 * every empty list says why it is empty.
 */
export type MetricCatalogStatus =
  | { status: 'loading' }
  | { status: 'error'; message: string; onRetry?: () => void }
  | { status: 'ready'; partial?: boolean };

const READY_CATALOG: MetricCatalogStatus = { status: 'ready' };

/** Most names the picker renders at once; typing narrows the rest. */
const PICKER_RENDER_CAP = 200;

type LoadState = 'loading' | 'error' | 'ready';

export interface MetricsExplorerProps {
  metricNames: string[];
  /** Catalog state for the picker; defaults to ready. */
  catalog?: MetricCatalogStatus;
  /** When set, the panel shows a remove control (multi-panel Metrics tab). */
  onRemove?: () => void;
  apiTimeRange: TimeRange;
  /** Preselect this metric on mount (e.g. `| metric <name>`); ignored if absent. */
  initialMetric?: string;
  /**
   * Scope the chart to a single OTLP service on mount (e.g.
   * `| metric <name> service=<svc>`). This seeds the `service_name` query param
   * — the promoted `otel_metrics.service_name` column, NOT a tag/attribute
   * filter — so the chart opens genuinely scoped (NAN-1564). Empty/absent ⇒
   * unscoped. Like `initialMetric`, it's a mount-time seed; the user can clear
   * it from the scope chip.
   */
  initialService?: string;
  /** Bump to force a monitors-list refresh (e.g. after creating one). */
  onMonitorCreated?: () => void;
}

export function MetricsExplorer({
  metricNames,
  catalog = READY_CATALOG,
  onRemove,
  apiTimeRange,
  initialMetric,
  initialService,
  onMonitorCreated,
}: MetricsExplorerProps) {
  // --- query state ---
  // A requested metric (`| metric <name>`) is honored even when the catalog
  // has not loaded or does not list it: the catalog is a convenience, not a
  // gate (NAN-4098).
  const [metric, setMetric] = useState(initialMetric || (metricNames[0] ?? ''));
  const [agg, setAgg] = useState<MetricAgg>('avg');
  const [groupBy, setGroupBy] = useState<string>(NO_GROUP);
  const [filters, setFilters] = useState<MetricFilter[]>([]);
  // Service scope → the promoted `otel_metrics.service_name` column (NAN-1564).
  // Seeded from `| metric x service=y`; '' ⇒ unscoped (all services).
  const [service, setService] = useState<string>(initialService?.trim() || '');
  const [stepSecs, setStepSecs] = useState(60);
  const [viz, setViz] = useState<MetricVizMode>('timeseries');

  // The catalog arrives independently of the explorer and monitor results.
  useEffect(() => {
    if (!metric && metricNames.length > 0) {
      setMetric(initialMetric || metricNames[0]);
    }
  }, [metric, metricNames, initialMetric]);

  // --- tag discovery ---
  const [tagKeys, setTagKeys] = useState<string[]>([]);
  const [tagState, setTagState] = useState<LoadState>('ready');

  // --- result ---
  const [series, setSeries] = useState<MetricSeries[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // NAN-1595: server cache status for the timeseries fetch + refresh bypass.
  const [cacheMeta, setCacheMeta] = useState<CacheMeta | null>(null);
  const [refreshNonce, setRefreshNonce] = useState(0);
  // NAN-1602: seed the bypass so a user-initiated search's first timeseries
  // fetch is live (no "cached" badge); later fetches read cache. No-op in the
  // Observability console (useIsLiveRun → false there).
  const bypassRef = useRef(useIsLiveRun());
  const refresh = useCallback(() => {
    bypassRef.current = true;
    setRefreshNonce((n) => n + 1);
  }, []);

  // --- dialogs ---
  const [monitorOpen, setMonitorOpen] = useState(false);
  const [dashOpen, setDashOpen] = useState(false);

  const { start, end } = apiTimeRange;

  // Reset selections only for a different metric, not a different time window.
  useEffect(() => {
    setGroupBy(NO_GROUP);
    setFilters([]);
  }, [metric]);

  // Discover tags over the same explicit window as the chart.
  useEffect(() => {
    if (!metric) {
      setTagKeys([]);
      setTagState('ready');
      return;
    }
    let cancelled = false;
    setTagKeys([]);
    setTagState('loading');
    api.observability
      .listMetricTags(metric, undefined, { start, end })
      .then((r) => {
        if (cancelled) return;
        setTagKeys(r.tag_keys ?? []);
        setTagState('ready');
      })
      .catch(() => {
        if (cancelled) return;
        setTagKeys([]);
        setTagState('error');
      });
    return () => {
      cancelled = true;
    };
  }, [metric, start, end]);

  // Fetch the series whenever any query input or the time range changes.
  useEffect(() => {
    if (!metric) {
      setSeries([]);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError(null);
    setCacheMeta(null);
    const bypass = bypassRef.current;
    bypassRef.current = false;
    api.observability
      .queryMetricsV2(
        {
          metric_name: metric,
          time_range: { start, end },
          step_secs: stepSecs,
          agg,
          group_by: groupBy === NO_GROUP ? undefined : groupBy,
          filters: filters.length ? filters : undefined,
          service_name: service || undefined,
        },
        { onMeta: (m) => { if (!cancelled) setCacheMeta(m); }, bypass }
      )
      .then((r) => {
        if (!cancelled) setSeries(r.series ?? []);
      })
      .catch((e: unknown) => {
        if (!cancelled) setError(e instanceof Error ? e.message : 'Failed to load metric');
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [metric, agg, groupBy, filters, stepSecs, start, end, service, refreshNonce]);

  const metricConfig = useMemo<MetricWidgetConfig>(
    () => ({
      metric_name: metric,
      agg,
      group_by: groupBy === NO_GROUP ? undefined : groupBy,
      filters: filters.length ? filters : undefined,
      service_name: service || undefined,
      viz: vizToWidgetViz(viz),
      step_secs: stepSecs,
    }),
    [metric, agg, groupBy, filters, service, viz, stepSecs]
  );

  const canActOnQuery = metric !== '' && series.length > 0;

  // NAN-1600: when embedded in the search page (`| metric <name>`), report the
  // real timeseries fetch to the footer (spinner → series count · query time).
  // settled = !loading so an idle unscoped explorer reports done (no time → the
  // footer simply shows nothing) rather than hanging on the spinner. No-op in
  // the Observability console / Metrics tab.
  useReportPhase2Status({
    loading,
    settled: !loading,
    error,
    totalCount: series.length,
  });

  return (
    <div className="rounded-md border border-border bg-card overflow-hidden">
      {/* ---- query builder row ---- */}
      <div className="px-3 py-2 border-b border-border flex items-center gap-2 flex-wrap">
        {/* metric */}
        <MetricPicker
          metric={metric}
          metricNames={metricNames}
          catalog={catalog}
          onChange={setMetric}
        />

        {/* aggregation */}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button
              type="button"
              className="inline-flex items-center gap-1.5 h-7 px-2 rounded-md border border-border text-[11.5px] hover:border-border-2 transition-colors font-mono text-fg-2"
            >
              <Sigma className="w-[11px] h-[11px] text-primary shrink-0" />
              {agg}
              <ChevronDown className="w-[10px] h-[10px] text-fg-4 shrink-0" />
            </button>
          </DropdownMenuTrigger>
          <DropdownMenuContent className="w-[140px]">
            {AGG_OPTS.map((a) => (
              <DropdownMenuItem key={a} onClick={() => setAgg(a)}>
                <span className="font-mono text-[11px]">{a}</span>
              </DropdownMenuItem>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>

        {/* group by */}
        <span className="font-mono text-[10.5px] text-fg-4">by</span>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button
              type="button"
              className="inline-flex items-center gap-1 h-7 px-2 rounded-md border border-border text-[11.5px] hover:border-border-2 transition-colors font-mono text-fg-2 max-w-[200px]"
            >
              <span className="truncate">{groupBy === NO_GROUP ? '(none)' : groupBy}</span>
              <ChevronDown className="w-[10px] h-[10px] text-fg-4 shrink-0" />
            </button>
          </DropdownMenuTrigger>
          <DropdownMenuContent className="w-[220px] max-h-[300px] overflow-y-auto">
            <DropdownMenuItem onClick={() => setGroupBy(NO_GROUP)}>
              <span className="font-mono text-[11px] text-fg-3">(none)</span>
            </DropdownMenuItem>
            {tagKeys.length === 0 && (
              <div className="px-2 py-1.5 text-[11px] text-fg-4">
                {!metric
                  ? 'Pick a metric first.'
                  : tagState === 'loading'
                    ? 'Loading tags…'
                    : tagState === 'error'
                      ? 'Could not load tags for this metric.'
                      : 'No tags on this metric in this range.'}
              </div>
            )}
            {tagKeys.map((k) => (
              <DropdownMenuItem key={k} onClick={() => setGroupBy(k)}>
                <span className="font-mono text-[11px] truncate">{k}</span>
              </DropdownMenuItem>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>

        <div className="flex-1" />

        {/* step */}
        <div className="flex items-center gap-px rounded-md bg-foreground/5 border border-border p-0.5">
          {STEP_OPTS.map(([label, secs]) => (
            <button
              key={secs}
              type="button"
              onClick={() => setStepSecs(secs)}
              className={cn(
                'px-1.5 py-0.5 rounded-[3px] text-[10px] font-mono transition-colors',
                secs === stepSecs
                  ? 'bg-primary/15 text-primary font-semibold'
                  : 'text-fg-3 hover:text-foreground'
              )}
            >
              {label}
            </button>
          ))}
        </div>

        {loading && <LoadingIcon className="w-3.5 h-3.5 text-fg-4" />}
        <span className="flex-1" />
        <CachedNotice meta={cacheMeta} onRefresh={refresh} refreshing={loading} />
        {onRemove && (
          <button
            type="button"
            onClick={onRemove}
            className="text-fg-4 hover:text-destructive w-6 h-6 flex items-center justify-center rounded"
            aria-label="Remove panel"
            title="Remove panel"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        )}
      </div>

      {/* ---- filters row ---- */}
      <FiltersRow
        metric={metric}
        tagKeys={tagKeys}
        tagState={tagState}
        apiTimeRange={apiTimeRange}
        filters={filters}
        onChange={setFilters}
        service={service}
        onClearService={() => setService('')}
      />

      {/* ---- viz switcher + actions ---- */}
      <div className="px-3 py-2 border-b border-border flex items-center gap-2 flex-wrap">
        <div className="flex items-center gap-px rounded-md bg-foreground/5 border border-border p-0.5">
          {VIZ_OPTS.map(({ mode, label, icon: Icon }) => (
            <button
              key={mode}
              type="button"
              onClick={() => setViz(mode)}
              title={label}
              className={cn(
                'inline-flex items-center gap-1 px-1.5 py-0.5 rounded-[3px] text-[10.5px] transition-colors',
                viz === mode
                  ? 'bg-primary/15 text-primary font-semibold'
                  : 'text-fg-3 hover:text-foreground'
              )}
            >
              <Icon className="w-[11px] h-[11px]" />
              {label}
            </button>
          ))}
        </div>

        <div className="flex-1" />

        <Button
          variant="outline"
          className="h-7 gap-1.5 text-[11px]"
          disabled={!canActOnQuery}
          onClick={() => setDashOpen(true)}
        >
          <LayoutDashboard className="w-[12px] h-[12px]" />
          Add to dashboard
        </Button>
        <Button
          variant="outline"
          className="h-7 gap-1.5 text-[11px]"
          disabled={metric === ''}
          onClick={() => setMonitorOpen(true)}
        >
          <AlertCircle className="w-[12px] h-[12px]" />
          Create monitor
        </Button>
      </div>

      {/* ---- chart body ---- */}
      <div className="p-3">
        {error ? (
          <div className="flex items-center justify-center gap-2 h-[220px] text-[12px] text-destructive">
            <AlertCircle className="w-4 h-4" />
            {error}
          </div>
        ) : !metric ? (
          <div className="flex items-center justify-center h-[220px] text-[12px] text-fg-3">
            {catalog.status === 'loading'
              ? 'Loading the metric catalog… or type a metric name in the picker.'
              : 'Pick or type a metric to chart.'}
          </div>
        ) : loading && series.length === 0 ? (
          <div className="flex items-center justify-center h-[220px]">
            <LoadingIcon className="w-5 h-5 text-fg-4" />
          </div>
        ) : series.length === 0 || series.every((s) => s.points.length === 0) ? (
          <div className="py-12 text-center text-[12px] text-fg-3">
            No samples for this metric in the selected range and filters. A catalog entry can outlive its latest samples.
            <TelemetrySetupHint />
          </div>
        ) : (
          <MetricViz mode={viz} series={series} metricName={metric} height={240} />
        )}
      </div>

      {/* legend (multi-series) */}
      {groupBy !== NO_GROUP && series.length > 0 && (
        <div className="px-3 pb-2.5 -mt-1 flex flex-wrap gap-x-3 gap-y-1">
          {series.slice(0, 12).map((s, i) => (
            <span key={s.key || i} className="inline-flex items-center gap-1.5 text-[10.5px]">
              <span
                className="w-2 h-2 rounded-sm"
                style={{ background: seriesColor(i) }}
              />
              <span className="font-mono text-fg-2 truncate max-w-[160px]">{s.key || '(empty)'}</span>
            </span>
          ))}
          {series.length > 12 && (
            <span className="text-[10.5px] text-fg-4 font-mono">+{series.length - 12} more</span>
          )}
        </div>
      )}

      <MetricMonitorDialog
        open={monitorOpen}
        onOpenChange={setMonitorOpen}
        seed={{
          metric_name: metric,
          agg,
          // O31 (NAN-1721): carry the active service scope (promoted
          // `service_name` column, NAN-1564) so the monitor evaluates the same
          // scope the chart shows. '' ⇒ undefined = fleet-wide.
          service_name: service || undefined,
          group_by: groupBy === NO_GROUP ? undefined : groupBy,
          filters,
        }}
        onCreated={onMonitorCreated}
      />
      <AddMetricToDashboardDialog
        open={dashOpen}
        onOpenChange={setDashOpen}
        metricConfig={metricConfig}
        defaultTitle={`${agg}(${metric})`}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Metric-name picker: type to filter the catalog, or chart any typed name.
// ---------------------------------------------------------------------------
function MetricPicker({
  metric,
  metricNames,
  catalog,
  onChange,
}: {
  metric: string;
  metricNames: string[];
  catalog: MetricCatalogStatus;
  onChange: (m: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [text, setText] = useState('');
  const typed = text.trim();
  const matches = useMemo(() => {
    const needle = typed.toLowerCase();
    return needle ? metricNames.filter((m) => m.toLowerCase().includes(needle)) : metricNames;
  }, [metricNames, typed]);
  const shown = matches.slice(0, PICKER_RENDER_CAP);
  const canUseTyped = typed !== '' && !metricNames.includes(typed);

  const choose = (m: string) => {
    onChange(m);
    setText('');
    setOpen(false);
  };

  let emptyNote: string | null = null;
  if (shown.length === 0) {
    if (catalog.status === 'loading') emptyNote = null;
    else if (catalog.status === 'error') emptyNote = 'Metric catalog unavailable. Type a metric name above.';
    else if (typed) emptyNote = 'No catalog match. Press Enter to chart the typed name.';
    else emptyNote = 'No metrics in the catalog window. Type a metric name above.';
  }

  return (
    <DropdownMenu
      open={open}
      onOpenChange={(next) => {
        setOpen(next);
        if (!next) setText('');
      }}
    >
      <DropdownMenuTrigger asChild>
        <button
          type="button"
          className="inline-flex items-center gap-1.5 h-7 px-2 rounded-md border border-border text-[11.5px] hover:border-border-2 transition-colors max-w-[300px]"
        >
          <LineChart className="w-[11px] h-[11px] text-primary shrink-0" />
          <span className="font-mono text-foreground truncate">{metric || 'select metric'}</span>
          <ChevronDown className="w-[10px] h-[10px] text-fg-4 shrink-0" />
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent className="w-[320px] max-h-[360px] overflow-y-auto">
        <div className="p-1.5 border-b border-border">
          <Input
            autoFocus
            value={text}
            onChange={(e) => setText(e.target.value)}
            onKeyDown={(e) => {
              // Keep the menu's typeahead from stealing keystrokes.
              e.stopPropagation();
              if (e.key === 'Enter' && typed) {
                e.preventDefault();
                choose(typed);
              }
            }}
            placeholder="Filter or type a metric name"
            aria-label="Metric name"
            className="h-7 font-mono text-[11px]"
          />
        </div>
        {catalog.status === 'loading' && (
          <div role="status" className="px-2 py-1.5 flex items-center gap-1.5 text-[11px] text-fg-3">
            <LoadingIcon className="w-3 h-3" /> Loading metric catalog…
          </div>
        )}
        {catalog.status === 'error' && (
          <div role="alert" className="px-2 py-1.5 flex items-center gap-1.5 text-[11px] text-destructive">
            <AlertCircle className="w-3 h-3 shrink-0" />
            <span className="truncate">{catalog.message}</span>
            {catalog.onRetry && (
              <button
                type="button"
                onClick={catalog.onRetry}
                className="ml-auto inline-flex items-center gap-1 text-fg-2 hover:text-primary"
              >
                <RotateCw className="w-3 h-3" /> Retry
              </button>
            )}
          </div>
        )}
        {canUseTyped && (
          <DropdownMenuItem onClick={() => choose(typed)}>
            <span className="text-[11px] text-fg-3 shrink-0">Use</span>
            <span className="font-mono text-[11px] truncate">{typed}</span>
          </DropdownMenuItem>
        )}
        {emptyNote && <div className="px-2 py-1.5 text-[11px] text-fg-3">{emptyNote}</div>}
        {shown.map((m) => (
          <DropdownMenuItem key={m} onClick={() => choose(m)}>
            <span className="font-mono text-[11px] truncate">{m}</span>
          </DropdownMenuItem>
        ))}
        {matches.length > shown.length && (
          <div className="px-2 py-1.5 font-mono text-[10.5px] text-fg-4">
            +{matches.length - shown.length} more · type to narrow
          </div>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

// ---------------------------------------------------------------------------
// Tag filters row — add key=value filters; values discovered per key.
// ---------------------------------------------------------------------------
function FiltersRow({
  metric,
  tagKeys,
  tagState,
  apiTimeRange,
  filters,
  onChange,
  service,
  onClearService,
}: {
  metric: string;
  tagKeys: string[];
  tagState: LoadState;
  apiTimeRange: TimeRange;
  filters: MetricFilter[];
  onChange: (next: MetricFilter[]) => void;
  /** Active `service_name` scope (promoted column, NAN-1564); '' ⇒ unscoped. */
  service: string;
  onClearService: () => void;
}) {
  const [pendingKey, setPendingKey] = useState<string | null>(null);
  const [pendingValues, setPendingValues] = useState<string[]>([]);
  const [valuesLoading, setValuesLoading] = useState(false);
  const [valuesError, setValuesError] = useState(false);
  const valuesRequest = useRef(0);
  const { start, end } = apiTimeRange;
  useEffect(() => {
    setPendingKey(null);
    setPendingValues([]);
    setValuesLoading(false);
    return () => {
      valuesRequest.current += 1;
    };
  }, [metric, start, end]);

  const loadValues = useCallback(
    (key: string) => {
      const request = ++valuesRequest.current;
      setPendingKey(key);
      setPendingValues([]);
      setValuesLoading(true);
      setValuesError(false);
      api.observability
        .listMetricTags(metric, key, { start, end })
        .then((r) => {
          if (request === valuesRequest.current) setPendingValues(r.tag_values ?? []);
        })
        .catch(() => {
          if (request === valuesRequest.current) {
            setPendingValues([]);
            setValuesError(true);
          }
        })
        .finally(() => {
          if (request === valuesRequest.current) setValuesLoading(false);
        });
    },
    [metric, start, end]
  );

  const addFilter = (key: string, value: string) => {
    onChange([...filters.filter((f) => !(f.key === key && f.value === value)), { key, value }]);
    setPendingKey(null);
  };

  return (
    <div className="px-3 py-1.5 border-b border-border flex items-center gap-1.5 flex-wrap min-h-[34px]">
      <span className="font-mono text-[10px] uppercase tracking-[0.1em] text-fg-4">filters</span>

      {/* Service scope chip (promoted `service_name` column, NAN-1564) — visually
          distinct from tag filters so it's clear this scopes by service. */}
      {service && (
        <span className="inline-flex items-center gap-1 h-6 pl-2 pr-1 rounded-md border border-primary/40 bg-primary/[0.08] text-[10.5px] font-mono text-fg-2">
          service=<span className="text-primary font-semibold">{service}</span>
          <button
            type="button"
            onClick={onClearService}
            className="text-fg-4 hover:text-destructive w-4 h-4 flex items-center justify-center rounded"
            aria-label="Clear service scope"
          >
            <X className="w-3 h-3" />
          </button>
        </span>
      )}

      {filters.map((f, i) => (
        <span
          key={`${f.key}=${f.value}-${i}`}
          className="inline-flex items-center gap-1 h-6 pl-2 pr-1 rounded-md border border-border bg-foreground/[0.03] text-[10.5px] font-mono text-fg-2"
        >
          {f.key}=<span className="text-foreground">{f.value}</span>
          <button
            type="button"
            onClick={() => onChange(filters.filter((_, j) => j !== i))}
            className="text-fg-4 hover:text-destructive w-4 h-4 flex items-center justify-center rounded"
            aria-label="Remove filter"
          >
            <X className="w-3 h-3" />
          </button>
        </span>
      ))}

      {/* add-filter: pick a key, then a value */}
      <DropdownMenu
        onOpenChange={(open) => {
          if (!open) setPendingKey(null);
        }}
      >
        <DropdownMenuTrigger asChild>
          <button
            type="button"
            disabled={tagKeys.length === 0}
            title={
              tagKeys.length > 0
                ? undefined
                : !metric
                  ? 'Pick a metric first'
                  : tagState === 'loading'
                    ? 'Loading tags…'
                    : tagState === 'error'
                      ? 'Could not load tags for this metric'
                      : 'No tags on this metric in this range'
            }
            className="inline-flex items-center gap-1 h-6 px-1.5 rounded-md border border-dashed border-border-2 text-[10.5px] text-fg-3 hover:text-primary hover:border-primary/40 transition-colors disabled:opacity-40"
          >
            <Plus className="w-3 h-3" /> filter
          </button>
        </DropdownMenuTrigger>
        <DropdownMenuContent className="w-[220px] max-h-[320px] overflow-y-auto">
          {pendingKey == null ? (
            <>
              <div className="px-2 py-1 text-[9.5px] uppercase tracking-[0.1em] text-fg-4">
                Tag key
              </div>
              {tagKeys.map((k) => (
                <DropdownMenuItem
                  key={k}
                  onSelect={(e) => {
                    e.preventDefault();
                    loadValues(k);
                  }}
                >
                  <span className="font-mono text-[11px] truncate">{k}</span>
                </DropdownMenuItem>
              ))}
            </>
          ) : (
            <>
              <div className="px-2 py-1 text-[9.5px] uppercase tracking-[0.1em] text-fg-4 flex items-center gap-1">
                {pendingKey}
                {valuesLoading && <LoadingIcon className="w-3 h-3" />}
              </div>
              {!valuesLoading && pendingValues.length === 0 && (
                <div className="px-2 py-1.5 text-[11px] text-fg-4">
                  {valuesError ? 'Could not load values.' : 'No values in this range.'}
                </div>
              )}
              {pendingValues.map((v) => (
                <DropdownMenuItem key={v} onClick={() => addFilter(pendingKey, v)}>
                  <span className="font-mono text-[11px] truncate">{v}</span>
                </DropdownMenuItem>
              ))}
            </>
          )}
        </DropdownMenuContent>
      </DropdownMenu>
    </div>
  );
}

export default MetricsExplorer;
