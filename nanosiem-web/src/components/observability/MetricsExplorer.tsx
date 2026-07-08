// SPDX-License-Identifier: AGPL-3.0-or-later

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
  Loader2,
  Plus,
  Sigma,
  X,
} from 'lucide-react';

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

export interface MetricsExplorerProps {
  metricNames: string[];
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
  apiTimeRange,
  initialMetric,
  initialService,
  onMonitorCreated,
}: MetricsExplorerProps) {
  // --- query state ---
  const [metric, setMetric] = useState(
    initialMetric && metricNames.includes(initialMetric)
      ? initialMetric
      : (metricNames[0] ?? '')
  );
  const [agg, setAgg] = useState<MetricAgg>('avg');
  const [groupBy, setGroupBy] = useState<string>(NO_GROUP);
  const [filters, setFilters] = useState<MetricFilter[]>([]);
  // Service scope → the promoted `otel_metrics.service_name` column (NAN-1564).
  // Seeded from `| metric x service=y`; '' ⇒ unscoped (all services).
  const [service, setService] = useState<string>(initialService?.trim() || '');
  const [stepSecs, setStepSecs] = useState(60);
  const [viz, setViz] = useState<MetricVizMode>('timeseries');

  // --- tag discovery ---
  const [tagKeys, setTagKeys] = useState<string[]>([]);

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

  // Load tag keys when the metric changes (resets group/filter selection).
  useEffect(() => {
    if (!metric) {
      setTagKeys([]);
      return;
    }
    let cancelled = false;
    api.observability
      .listMetricTags(metric)
      .then((r) => {
        if (!cancelled) setTagKeys(r.tag_keys ?? []);
      })
      .catch(() => {
        if (!cancelled) setTagKeys([]);
      });
    setGroupBy(NO_GROUP);
    setFilters([]);
    return () => {
      cancelled = true;
    };
  }, [metric]);

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
        <MetricPicker metric={metric} metricNames={metricNames} onChange={setMetric} />

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
              <div className="px-2 py-1.5 text-[11px] text-fg-4">No tags on this metric.</div>
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

        {loading && <Loader2 className="w-3.5 h-3.5 animate-spin text-fg-4" />}
        <span className="flex-1" />
        <CachedNotice meta={cacheMeta} onRefresh={refresh} refreshing={loading} />
      </div>

      {/* ---- filters row ---- */}
      <FiltersRow
        metric={metric}
        tagKeys={tagKeys}
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
            Pick a metric to chart.
          </div>
        ) : loading && series.length === 0 ? (
          <div className="flex items-center justify-center h-[220px]">
            <Loader2 className="w-5 h-5 animate-spin text-fg-4" />
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
                style={{
                  background: [
                    '#3b82f6',
                    '#22c55e',
                    '#eab308',
                    '#ef4444',
                    '#a855f7',
                    '#06b6d4',
                    '#f97316',
                    '#ec4899',
                  ][i % 8],
                }}
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
// Metric-name picker (searchable-ish dropdown)
// ---------------------------------------------------------------------------
function MetricPicker({
  metric,
  metricNames,
  onChange,
}: {
  metric: string;
  metricNames: string[];
  onChange: (m: string) => void;
}) {
  return (
    <DropdownMenu>
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
        {metricNames.length === 0 && (
          <div className="px-2 py-1.5 text-[11px] text-fg-3">No metrics ingested.</div>
        )}
        {metricNames.map((m) => (
          <DropdownMenuItem key={m} onClick={() => onChange(m)}>
            <span className="font-mono text-[11px] truncate">{m}</span>
          </DropdownMenuItem>
        ))}
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
  filters,
  onChange,
  service,
  onClearService,
}: {
  metric: string;
  tagKeys: string[];
  filters: MetricFilter[];
  onChange: (next: MetricFilter[]) => void;
  /** Active `service_name` scope (promoted column, NAN-1564); '' ⇒ unscoped. */
  service: string;
  onClearService: () => void;
}) {
  const [pendingKey, setPendingKey] = useState<string | null>(null);
  const [pendingValues, setPendingValues] = useState<string[]>([]);
  const [valuesLoading, setValuesLoading] = useState(false);

  const loadValues = useCallback(
    (key: string) => {
      setPendingKey(key);
      setPendingValues([]);
      setValuesLoading(true);
      api.observability
        .listMetricTags(metric, key)
        .then((r) => setPendingValues(r.tag_values ?? []))
        .catch(() => setPendingValues([]))
        .finally(() => setValuesLoading(false));
    },
    [metric]
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
                {valuesLoading && <Loader2 className="w-3 h-3 animate-spin" />}
              </div>
              {!valuesLoading && pendingValues.length === 0 && (
                <div className="px-2 py-1.5 text-[11px] text-fg-4">No values.</div>
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
