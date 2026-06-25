// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * MetricViz (NAN-1540)
 *
 * Visualization switcher for the Metrics explorer. Renders a metrics-v2
 * `series[]` payload one of several ways:
 *
 *   timeseries  — line / area / bars (multi-series legend), via REDChart
 *   toplist     — series ranked by latest|avg value
 *   query_value — a single big scalar (first series, latest point)
 *   distribution— per-series latest value as a horizontal distribution bar set
 *   heatmap     — time × series intensity grid (good for histogram percentiles
 *                 or many group-by series)
 *
 * Presentational only — data in, SVG/DOM out. The explorer owns fetching.
 */

import { useMemo } from 'react';
import { REDChart, Sparkline, type RedSeries } from './charts';
import type { MetricSeries } from '@/lib/api/types';

export type MetricVizMode =
  | 'timeseries'
  | 'area'
  | 'bars'
  | 'toplist'
  | 'query_value'
  | 'distribution'
  | 'heatmap';

// Shared palette (matches ObsMetricWidget / VisualizationRenderer so a metric
// reads the same on the explorer and on a dashboard).
export const METRIC_SERIES_COLORS = [
  '#3b82f6',
  '#22c55e',
  '#eab308',
  '#ef4444',
  '#a855f7',
  '#06b6d4',
  '#f97316',
  '#ec4899',
];

export function fmtMetric(v: number, unit?: string): string {
  const a = Math.abs(v);
  let n: string;
  if (a >= 1_000_000) n = (v / 1_000_000).toFixed(1).replace(/\.0$/, '') + 'M';
  else if (a >= 1_000) n = (v / 1_000).toFixed(1).replace(/\.0$/, '') + 'k';
  else if (a >= 100 || a === 0) n = String(Math.round(v));
  else if (a >= 1) n = v.toFixed(1).replace(/\.0$/, '');
  else n = v.toPrecision(2);
  if (!unit) return n;
  return unit.startsWith('%') ? `${n}${unit}` : `${n} ${unit}`;
}

const latestOf = (s: MetricSeries): number =>
  s.points.length ? s.points[s.points.length - 1].v : 0;
const avgOf = (s: MetricSeries): number =>
  s.points.length ? s.points.reduce((a, p) => a + p.v, 0) / s.points.length : 0;

export interface MetricVizProps {
  mode: MetricVizMode;
  series: MetricSeries[];
  metricName: string;
  unit?: string;
  /** Tall enough for the explorer's stacked panel. */
  height?: number;
  /** For toplist/distribution: rank by latest or average value. */
  rankBy?: 'latest' | 'avg';
}

export function MetricViz({
  mode,
  series,
  metricName,
  unit,
  height = 220,
  rankBy = 'latest',
}: MetricVizProps) {
  const nonEmpty = series.filter((s) => s.points.length > 0);

  if (nonEmpty.length === 0) {
    return (
      <div
        className="flex items-center justify-center text-[12px] text-fg-3"
        style={{ height }}
      >
        No data for this query in range.
      </div>
    );
  }

  if (mode === 'query_value') {
    return <QueryValue series={nonEmpty} metricName={metricName} unit={unit} height={height} />;
  }

  if (mode === 'toplist' || mode === 'distribution') {
    return (
      <RankedList
        series={nonEmpty}
        metricName={metricName}
        unit={unit}
        height={height}
        rankBy={rankBy}
        showSparkline={mode === 'distribution'}
      />
    );
  }

  if (mode === 'heatmap') {
    return <Heatmap series={nonEmpty} unit={unit} height={height} />;
  }

  // timeseries family — line / area / bars
  return (
    <TimeseriesChart
      series={nonEmpty}
      metricName={metricName}
      unit={unit}
      height={height}
      variant={mode}
    />
  );
}

// ---------------------------------------------------------------------------
// query_value — single scalar
// ---------------------------------------------------------------------------
function QueryValue({
  series,
  metricName,
  unit,
  height,
}: {
  series: MetricSeries[];
  metricName: string;
  unit?: string;
  height: number;
}) {
  const value = latestOf(series[0]);
  return (
    <div className="flex flex-col items-center justify-center" style={{ height }}>
      <div className="font-mono text-5xl font-semibold text-foreground tabular-nums">
        {fmtMetric(value, unit)}
      </div>
      <div className="mt-2 font-mono text-[10px] uppercase tracking-[0.12em] text-fg-3 truncate max-w-full px-4">
        {series[0].key || metricName}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// toplist / distribution — ranked bar list
// ---------------------------------------------------------------------------
function RankedList({
  series,
  metricName,
  unit,
  height,
  rankBy,
  showSparkline,
}: {
  series: MetricSeries[];
  metricName: string;
  unit?: string;
  height: number;
  rankBy: 'latest' | 'avg';
  showSparkline: boolean;
}) {
  const ranked = useMemo(() => {
    const valueOf = rankBy === 'avg' ? avgOf : latestOf;
    return [...series]
      .map((s) => ({ key: s.key, value: valueOf(s), points: s.points.map((p) => p.v) }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 25);
  }, [series, rankBy]);
  const max = Math.max(1, ...ranked.map((r) => r.value));

  return (
    <div className="overflow-auto flex flex-col gap-1 py-1 pr-1" style={{ maxHeight: height }}>
      {ranked.map((r, i) => (
        <div key={r.key || `__${i}`} className="flex items-center gap-2">
          <span className="font-mono text-[9px] text-fg-4 w-5 tabular-nums text-right shrink-0">
            {i + 1}
          </span>
          <span
            className="w-2 h-2 rounded-sm shrink-0"
            style={{ background: METRIC_SERIES_COLORS[i % METRIC_SERIES_COLORS.length] }}
          />
          <span className="text-[11.5px] text-foreground truncate flex-1 font-mono">
            {r.key || metricName}
          </span>
          {showSparkline && (
            <Sparkline
              data={r.points}
              color={METRIC_SERIES_COLORS[i % METRIC_SERIES_COLORS.length]}
              w={64}
              h={16}
            />
          )}
          <div className="relative w-28 h-1.5 rounded-full bg-foreground/10 overflow-hidden shrink-0">
            <div
              className="absolute inset-y-0 left-0 rounded-full"
              style={{
                width: `${(r.value / max) * 100}%`,
                background: METRIC_SERIES_COLORS[i % METRIC_SERIES_COLORS.length],
              }}
            />
          </div>
          <span className="font-mono text-[11px] text-fg-2 tabular-nums w-20 text-right shrink-0">
            {fmtMetric(r.value, unit)}
          </span>
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// heatmap — time (x) × series (y), value mapped to opacity
// ---------------------------------------------------------------------------
function Heatmap({
  series,
  unit,
  height,
}: {
  series: MetricSeries[];
  unit?: string;
  height: number;
}) {
  // Align on the longest series's bucket axis (backend buckets all series on the
  // same step). Cap rows for legibility.
  const rows = series.slice(0, 30);
  const longest = rows.reduce((a, b) => (b.points.length > a.points.length ? b : a), rows[0]);
  const cols = longest.points.length;
  const max = Math.max(1e-9, ...rows.flatMap((s) => s.points.map((p) => p.v)));

  return (
    <div className="overflow-auto" style={{ maxHeight: height }}>
      <div className="flex flex-col gap-[2px] min-w-fit">
        {rows.map((s, ri) => (
          <div key={s.key || `__${ri}`} className="flex items-center gap-2">
            <span className="font-mono text-[10px] text-fg-3 truncate w-28 shrink-0 text-right">
              {s.key || 'value'}
            </span>
            <div className="flex gap-[2px]">
              {Array.from({ length: cols }).map((_, ci) => {
                const v = s.points[ci]?.v ?? 0;
                const intensity = Math.max(0.04, v / max);
                return (
                  <div
                    key={ci}
                    className="w-[10px] h-[12px] rounded-[1px]"
                    style={{
                      background: 'var(--color-brand)',
                      opacity: intensity,
                    }}
                    title={`${fmtMetric(v, unit)}${s.points[ci] ? ` @ ${new Date(s.points[ci].t).toISOString().slice(11, 16)}` : ''}`}
                  />
                );
              })}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// timeseries — line / area / bars via REDChart
// ---------------------------------------------------------------------------
function TimeseriesChart({
  series,
  metricName,
  unit,
  height,
  variant,
}: {
  series: MetricSeries[];
  metricName: string;
  unit?: string;
  height: number;
  variant: 'timeseries' | 'area' | 'bars';
}) {
  const longest = series.reduce((a, b) => (b.points.length > a.points.length ? b : a), series[0]);
  const buckets = longest.points.map((p) => p.t);
  const redSeries: RedSeries[] = series.map((s, i) => ({
    points: s.points.map((p) => p.v),
    color: METRIC_SERIES_COLORS[i % METRIC_SERIES_COLORS.length],
    label: s.key || metricName,
    fill: variant === 'area' || (variant === 'timeseries' && series.length === 1),
  }));

  // REDChart renders lines + optional fill; "bars" reuses the area form so a
  // single SVG primitive serves all three timeseries variants without a second
  // chart module. (Distinct bar geometry would need a new REDChart prop owned by
  // fe-charts; deferred — area+fill reads correctly for metric volume.)
  return (
    <REDChart
      series={redSeries}
      buckets={buckets}
      height={height}
      unit={unit ? ` ${unit}` : ''}
      yFmt={(v) => fmtMetric(v)}
    />
  );
}

export default MetricViz;
