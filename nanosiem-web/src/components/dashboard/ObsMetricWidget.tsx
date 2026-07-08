// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * ObsMetricWidget (NAN-1540)
 *
 * Renderer for the `obs_metric` dashboard widget type. It does NOT fetch — the
 * dashboard's panel loader fetches the metrics-v2 timeseries (api.observability
 * .queryMetricsV2) and stashes the returned `series[]` into the panel data
 * state; this component reconstructs those series and renders them via the
 * observability charts module (REDChart) or as a top-list / single value.
 *
 * Series are passed through `PanelDataState.data` as one row per series:
 *   { key: string, points: [{ t, v }] }
 * which keeps metric widgets inside the existing Map<panelId, PanelDataState>
 * plumbing without a parallel state channel.
 */

import { useLayoutEffect, useMemo, useRef, useState } from 'react';
import { REDChart, type RedSeries } from '@/components/observability/charts';
import type {
  MetricWidgetConfig,
  MetricSeries,
  MetricSeriesPoint,
} from '@/lib/api';

// Same palette the dashboard VisualizationRenderer uses, so multi-series metric
// widgets read consistently against nPL/SQL panels on the same board.
const SERIES_COLORS = [
  '#3b82f6',
  '#22c55e',
  '#eab308',
  '#ef4444',
  '#a855f7',
  '#06b6d4',
  '#f97316',
  '#ec4899',
];

/** Coerce the loosely-typed panel-data rows back into MetricSeries[]. */
export function rowsToMetricSeries(rows: Record<string, unknown>[]): MetricSeries[] {
  return rows.map((row) => {
    const rawPoints = Array.isArray(row.points) ? row.points : [];
    const points: MetricSeriesPoint[] = rawPoints.map((p) => {
      const pt = p as { t?: unknown; v?: unknown };
      return { t: String(pt.t ?? ''), v: Number(pt.v ?? 0) };
    });
    return { key: typeof row.key === 'string' ? row.key : String(row.key ?? ''), points };
  });
}

/** MetricSeries[] -> the row shape stored in PanelDataState.data. */
export function metricSeriesToRows(series: MetricSeries[]): Record<string, unknown>[] {
  return series.map((s) => ({ key: s.key, points: s.points }));
}

// Chronological comparator for bucket timestamps. metrics-v2 emits absolute
// timestamps, so parse to epoch when possible; fall back to string order.
function compareBucket(a: string, b: string): number {
  const ta = Date.parse(a);
  const tb = Date.parse(b);
  if (!Number.isNaN(ta) && !Number.isNaN(tb)) return ta - tb;
  return a < b ? -1 : a > b ? 1 : 0;
}

// The union of every series' point timestamps, sorted chronologically. The
// backend buckets all series on the same step but does NOT gap-fill, so a quiet
// series simply omits buckets; the union axis lets us place each point by its
// own `t` instead of by array index (DSH7).
function unionBuckets(series: MetricSeries[]): string[] {
  const set = new Set<string>();
  for (const s of series) for (const p of s.points) set.add(p.t);
  return Array.from(set).sort(compareBucket);
}

function fmtValue(v: number, unit?: string): string {
  const n =
    Math.abs(v) >= 10_000
      ? new Intl.NumberFormat('en-US', { notation: 'compact', maximumFractionDigits: 1 }).format(v)
      : Number.isInteger(v)
        ? v.toLocaleString()
        : v.toFixed(2);
  return unit ? `${n}${unit.startsWith('%') ? '' : ' '}${unit}` : n;
}

export interface ObsMetricWidgetProps {
  config: MetricWidgetConfig;
  /** Series rows as stored in PanelDataState.data (see module doc). */
  data: Record<string, unknown>[];
}

export function ObsMetricWidget({ config, data }: ObsMetricWidgetProps) {
  const series = useMemo(() => rowsToMetricSeries(data), [data]);
  const viz = config.viz ?? 'timeseries';

  if (series.length === 0 || series.every((s) => s.points.length === 0)) {
    return (
      <div className="h-full flex items-center justify-center text-[12px] text-muted-foreground">
        No metric data in range.
      </div>
    );
  }

  if (viz === 'query_value') {
    // Single scalar: last point of the first series (the agg already collapses
    // the window when no group_by / a coarse step is chosen).
    const pts = series[0].points;
    const value = pts.length ? pts[pts.length - 1].v : 0;
    return (
      <div className="h-full flex flex-col items-center justify-center">
        <div className="font-mono text-4xl font-bold text-foreground">
          {fmtValue(value, config.unit)}
        </div>
        <div className="mt-1.5 font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground">
          {config.agg} · {config.metric_name}
        </div>
      </div>
    );
  }

  if (viz === 'toplist') {
    // Rank series by their value at the latest SHARED bucket (0 when the series
    // isn't reporting there), so a series that stopped reporting drops instead
    // of ranking high on a stale last-ever value. Because the backend buckets
    // all series on the same step, aligning by timestamp is exact (DSH7).
    const latest = unionBuckets(series).at(-1);
    const ranked = [...series]
      .map((s) => {
        const pt = latest != null ? s.points.find((p) => p.t === latest) : undefined;
        return { key: s.key, value: pt ? pt.v : 0 };
      })
      .sort((a, b) => b.value - a.value)
      .slice(0, 20);
    const max = Math.max(1, ...ranked.map((r) => r.value));
    return (
      <div className="h-full overflow-auto flex flex-col gap-1 py-1">
        {ranked.map((r, i) => (
          <div key={r.key || `__${i}`} className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-sm shrink-0" style={{ background: SERIES_COLORS[i % SERIES_COLORS.length] }} />
            <span className="text-[11.5px] text-foreground truncate flex-1 font-mono">
              {r.key || config.metric_name}
            </span>
            <div className="relative w-24 h-1.5 rounded-full bg-foreground/10 overflow-hidden shrink-0">
              <div
                className="absolute inset-y-0 left-0 rounded-full"
                style={{ width: `${(r.value / max) * 100}%`, background: SERIES_COLORS[i % SERIES_COLORS.length] }}
              />
            </div>
            <span className="font-mono text-[11px] text-muted-foreground tabular-nums w-16 text-right shrink-0">
              {fmtValue(r.value, config.unit)}
            </span>
          </div>
        ))}
      </div>
    );
  }

  // Default: timeseries via the observability REDChart. REDChart aligns every
  // series positionally to ONE bucket axis (`series[0].points.length` / the
  // shared `buckets` array), so we must resample each series onto the UNION of
  // all timestamps and place each point by its own `t`. Aligning by array index
  // (the old behavior) shifts a series that is missing early buckets, rendering
  // its spikes at the wrong time (DSH7). REDChart can't draw true gaps and NaN
  // would poison its y-scale, so absent buckets are filled with 0.
  const buckets = unionBuckets(series);
  const bucketIndex = new Map<string, number>(buckets.map((t, i): [string, number] => [t, i]));
  const redSeries: RedSeries[] = series.map((s, i) => {
    const points = new Array<number>(buckets.length).fill(0);
    for (const p of s.points) {
      const idx = bucketIndex.get(p.t);
      if (idx !== undefined) points[idx] = p.v;
    }
    return {
      points,
      color: SERIES_COLORS[i % SERIES_COLORS.length],
      label: s.key || config.metric_name,
      fill: series.length === 1,
    };
  });

  return (
    <ResponsiveRedChart
      series={redSeries}
      buckets={buckets}
      unit={config.unit ? ` ${config.unit}` : ''}
      yFmt={(v) => fmtValue(v, undefined)}
    />
  );
}

// REDChart takes a fixed pixel height; the panel content box is flexible, so we
// measure it and feed the height through. Width is REDChart's own concern (it
// uses an internal ResizeObserver).
function ResponsiveRedChart({
  series,
  buckets,
  unit,
  yFmt,
}: {
  series: RedSeries[];
  buckets: Array<number | string>;
  unit: string;
  yFmt: (v: number) => string;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const [h, setH] = useState(220);
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const ro = new ResizeObserver((entries) => {
      const ch = entries[0]?.contentRect.height;
      if (ch && ch > 40) setH(Math.round(ch));
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  return (
    <div ref={ref} className="h-full w-full">
      <REDChart series={series} buckets={buckets} height={h} unit={unit} yFmt={yFmt} />
    </div>
  );
}

export default ObsMetricWidget;
