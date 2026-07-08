// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * VisualizationRenderer Component
 * 
 * Renders different visualization types based on configuration.
 * Supports bar, line, area, pie charts using Recharts,
 * table visualization with sorting and pagination,
 * single value metric with thresholds, and timeline visualization.
 * 
 * Requirements: 3.1, 3.4, 3.5, 3.6, 3.7, 3.8
 */

import { useState, useMemo } from 'react';
import {
  BarChart,
  Bar,
  LineChart,
  Line,
  AreaChart,
  Area,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts';
import { Button } from '@/components/ui/button';
import { ChevronUp, ChevronDown, ChevronLeft, ChevronRight, TrendingUp, TrendingDown, Minus } from 'lucide-react';
import type { VisualizationType, VisualizationConfig, TableColumnConfig } from '@/lib/api';
import type { DrilldownPayload } from './drilldown';
import { TreeVisualization, type TreeNode } from '@/components/search/TreeVisualization';
import { RankedBarChart } from '@/components/search/RankedBarChart';
import { TransactionCards } from '@/components/search/TransactionCards';
import { FlowVisualization } from '@/components/search/FlowVisualization';

// Chart color palette matching the dark theme
// Uses CSS variable colors from index.css for consistency
// Primary colors: blue, green, yellow, red (matching chart-1 through chart-5)
// Extended palette for additional series
const CHART_COLORS = [
  '#3b82f6', // blue-500 (primary)
  '#22c55e', // green-500
  '#eab308', // yellow-500
  '#ef4444', // red-500
  '#a855f7', // purple-500
  '#06b6d4', // cyan-500
  '#f97316', // orange-500
  '#ec4899', // pink-500
];

// Consistent axis styling for dark theme
const AXIS_STYLE = {
  stroke: '#6b7280', // gray-500
  fontSize: 10,
  fontFamily: 'var(--font-mono)',
  tickLine: false,
  axisLine: false,
};

// Tooltip styling - uses CSS variables for theme awareness
const TOOLTIP_STYLE: React.CSSProperties = {
  backgroundColor: 'var(--popover)',
  border: '1px solid var(--border)',
  borderRadius: '0.75rem', // rounded-xl
  color: 'var(--popover-foreground)',
  fontFamily: 'var(--font-mono)',
  fontSize: '11px',
};

// Label styling for tooltips
const TOOLTIP_LABEL_STYLE: React.CSSProperties = {
  color: 'var(--muted-foreground)',
  fontFamily: 'var(--font-mono)',
  fontSize: '10px',
  textTransform: 'uppercase',
  letterSpacing: '0.08em',
};

// Compact format for fixed-size containers (donut center, single-value KPI).
// Below 10k stays comma-separated for legibility; above uses 5.5M / 12.3K so the
// digits fit inside the donut hole instead of being clipped by the ring.
function formatCompactNumber(n: number): string {
  if (Math.abs(n) < 10_000) return n.toLocaleString();
  return new Intl.NumberFormat('en-US', {
    notation: 'compact',
    maximumFractionDigits: 1,
  }).format(n);
}

// ---------------------------------------------------------------------------
// Column-role classification (DSH6 / DSH30 / DSH31 / DSH32 / DSH53)
//
// Search results arrive as objects with alphabetized keys and JSON-typed values,
// so `typeof` alone cannot tell a numeric GROUP-BY (dest_port, status_code,
// severity_id) from a numeric AGGREGATE (count, sum). When the panel-query
// response carries `column_order` (group-by fields first, aggregates last —
// CONTRACT 1) we use it to pick labels/values deterministically. Absent that we
// fall back to a time-key + aggregate-name heuristic so the common unaliased
// `stats count by <field>` shape is still correct.
// ---------------------------------------------------------------------------

// Aggregate output-column names nPL emits when the aggregation is not aliased.
const AGGREGATE_NAMES = new Set([
  'count', 'sum', 'avg', 'mean', 'min', 'max', 'median', 'mode', 'range',
  'stdev', 'stddev', 'var', 'variance', 'dc', 'estdc', 'distinct_count',
  'values', 'list', 'first', 'last', 'earliest', 'latest',
]);

function isAggregateName(key: string): boolean {
  const k = key.toLowerCase();
  return AGGREGATE_NAMES.has(k) || /^p\d{1,3}$/.test(k) || /^percentile\d*$/.test(k);
}

// A MEASURE is an aggregate output column (it sizes/plots as a value); every
// other column in a stats/timechart result is a DIMENSION (group-by), even when
// numeric (dest_port, status_code, severity_id). Catches unaliased aggregates
// and `<func>_<field>` forms (e.g. sum_bytes, avg_port). Fully-custom aliases
// (`... as foo`) fall through to the numeric fallback the callers apply.
const MEASURE_PREFIX =
  /^(count|sum|avg|mean|min|max|median|mode|range|stdev|stddev|var|variance|dc|estdc|distinct_count|distinct|values|list|first|last|earliest|latest|percentile|p\d{1,3})(_|$)/;
function isMeasureKey(key: string): boolean {
  return isAggregateName(key) || MEASURE_PREFIX.test(key.toLowerCase());
}

function isTimeLikeKey(key: string): boolean {
  const k = key.toLowerCase();
  return k.includes('time') || k.includes('bucket') || k === 'ts' || k === '_time';
}

// Aggregates whose "no rows" value is genuinely 0 (count/sum/distinct-count).
// avg/min/max/median/percentile of zero rows is undefined -> gap (null), so an
// empty bucket must NOT plunge the line to 0 (DSH30).
function isZeroFillAgg(key: string): boolean {
  const k = key.toLowerCase();
  return k === 'count' || k.startsWith('count') || k === 'sum' || k.startsWith('sum_')
    || k === 'dc' || k === 'estdc' || k.startsWith('distinct');
}

// Ordered column keys: honor `column_order` for the columns it names, then
// append any present-but-unlisted keys (e.g. eval outputs) in their natural order.
function orderedColumns(sample: Record<string, unknown>, columnOrder?: string[]): string[] {
  const present = Object.keys(sample ?? {});
  if (!columnOrder || columnOrder.length === 0) return present;
  const inOrder = columnOrder.filter(k => k in sample);
  const rest = present.filter(k => !inOrder.includes(k));
  return [...inOrder, ...rest];
}

// Pick the label / category column: a time bucket always wins; else with
// column_order the first column is the primary group-by (a label even when
// numeric); else the first non-numeric, then the first non-aggregate-named
// column, then the first column.
function pickLabelKey(
  sample: Record<string, unknown>,
  keys: string[],
  columnOrder?: string[]
): string {
  const isNum = (k: string) => typeof sample[k] === 'number';
  const timeKey = keys.find(isTimeLikeKey);
  if (timeKey) return timeKey;
  if (columnOrder && columnOrder.length) return keys[0];
  return keys.find(k => !isNum(k)) ?? keys.find(k => !isAggregateName(k)) ?? keys[0];
}

function parseTimeMs(v: unknown): number | null {
  if (v instanceof Date) return v.getTime();
  if (typeof v === 'string') {
    const t = Date.parse(v);
    return Number.isNaN(t) ? null : t;
  }
  return null;
}

// Infer the bucket width (ms) as the smallest positive gap between parseable
// time labels. Returns undefined when labels are not absolute timestamps
// (e.g. "10:00") so callers safely skip anchoring / densification.
function inferSpanMs(labels: unknown[]): number | undefined {
  const times = labels
    .map(parseTimeMs)
    .filter((t): t is number => t != null)
    .sort((a, b) => a - b);
  if (times.length < 2) return undefined;
  let min = Infinity;
  for (let i = 1; i < times.length; i++) {
    const d = times[i] - times[i - 1];
    if (d > 0 && d < min) min = d;
  }
  return Number.isFinite(min) ? min : undefined;
}

interface ColumnRoles {
  keys: string[];
  labelKey: string;
  /** Numeric aggregate / series columns (everything numeric except the label). */
  valueKeys: string[];
  timeKey?: string;
  isTimeSeries: boolean;
  /** Bucket width in ms for a time series with absolute timestamps. */
  spanMs?: number;
}

function classifyColumns(
  data: Record<string, unknown>[],
  columnOrder?: string[]
): ColumnRoles {
  const sample = data[0] ?? {};
  const keys = orderedColumns(sample, columnOrder);
  const isNum = (k: string) => typeof sample[k] === 'number';
  const timeKey = keys.find(isTimeLikeKey);
  const labelKey = pickLabelKey(sample, keys, columnOrder);
  // Values = numeric MEASURE columns only, so a numeric secondary group-by
  // (dest_port) stays a dimension rather than being plotted/summed as a metric
  // (DSH6). Fall back to all numeric non-label columns when nothing looks like an
  // aggregate (a `| table` projection, or fully-aliased aggregates).
  const measureKeys = keys.filter(k => k !== labelKey && isNum(k) && isMeasureKey(k));
  const valueKeys =
    measureKeys.length > 0 ? measureKeys : keys.filter(k => k !== labelKey && isNum(k));
  const isTimeSeries = !!timeKey && labelKey === timeKey;
  const spanMs = isTimeSeries ? inferSpanMs(data.map(r => r[labelKey])) : undefined;
  return { keys, labelKey, valueKeys, timeKey, isTimeSeries, spanMs };
}

// Densify a time series so missing WHOLE buckets show as gaps instead of the
// categorical X axis silently collapsing an outage into a continuous line
// (DSH30). Only runs when every label is an absolute timestamp and a uniform
// step is inferable; otherwise the input is returned unchanged. Inserted gap
// rows fill each value column per its aggregate type (0 for count/sum, null for
// avg/percentile — a Recharts gap).
function densifyTimeBuckets(
  rows: Record<string, unknown>[],
  labelKey: string,
  spanMs: number,
  fillCols: Array<{ key: string; fill: number | null }>
): Record<string, unknown>[] {
  if (rows.length < 2 || spanMs <= 0) return rows;
  const parsed = rows.map(r => ({ r, ms: parseTimeMs(r[labelKey]) }));
  if (parsed.some(p => p.ms == null)) return rows;
  const sorted = parsed.sort((a, b) => a.ms! - b.ms!);
  const first = sorted[0].ms!;
  const last = sorted[sorted.length - 1].ms!;
  const steps = Math.round((last - first) / spanMs);
  // Guard: bail if the span estimate is degenerate or would explode the axis.
  if (!Number.isFinite(steps) || steps <= 0 || steps > 2000 || steps < sorted.length - 1) {
    return rows;
  }
  const slots: Array<Record<string, unknown> | null> = new Array(steps + 1).fill(null);
  for (const { r, ms } of sorted) {
    const idx = Math.round((ms! - first) / spanMs);
    if (idx >= 0 && idx <= steps && slots[idx] === null) slots[idx] = r;
  }
  return slots.map((slot, i) => {
    if (slot) return slot;
    const gap: Record<string, unknown> = { [labelKey]: new Date(first + i * spanMs).toISOString() };
    for (const { key, fill } of fillCols) gap[key] = fill;
    return gap;
  });
}

/**
 * Detect and pivot split-by data format for timechart queries.
 *
 * Input format (row-based, from `| timechart count by action`):
 *   [{ time_bucket: "10:00", action: "cache_miss", count: 45 },
 *    { time_bucket: "10:00", action: "cache_hit", count: 120 }]
 *
 * Output format (columnar, for multi-series charts):
 *   [{ time_bucket: "10:00", cache_miss: 45, cache_hit: 120 }]
 *
 * Label/value roles come from {@link classifyColumns} (column_order-aware), so a
 * numeric group-by is kept as the category axis rather than plotted as a series
 * (DSH6). Absent split combos and missing whole buckets are filled per the
 * aggregate type (DSH30).
 */
function pivotSplitByData(
  data: Record<string, unknown>[],
  columnOrder?: string[]
): {
  data: Record<string, unknown>[];
  labelKey: string;
  valueKeys: string[];
  wasPivoted: boolean;
  isTimeSeries: boolean;
  timeKey?: string;
  spanMs?: number;
} {
  if (!data.length) {
    return { data: [], labelKey: '', valueKeys: [], wasPivoted: false, isTimeSeries: false };
  }

  const { keys, labelKey, timeKey, isTimeSeries, spanMs } = classifyColumns(data, columnOrder);
  const sample = data[0];
  const isNum = (k: string) => typeof sample[k] === 'number';

  const rest = keys.filter(k => k !== labelKey);
  // Measures = aggregate columns; dimensions = everything else (incl. numeric
  // group-bys). This keeps a numeric split-by (e.g. `timechart count by
  // dest_port`) as the series dimension rather than a second plotted metric
  // (DSH6). Fall back to numeric-typed detection when no column looks like an
  // aggregate (fully-aliased result).
  const measureRest = rest.filter(k => isNum(k) && isMeasureKey(k));
  const effectiveMeasures = measureRest.length > 0 ? measureRest : rest.filter(isNum);
  const dimensionRest = rest.filter(k => !effectiveMeasures.includes(k));

  // Split-by (long -> wide): exactly one extra dimension column plus a single
  // value column, e.g. `timechart count by action` or `stats count by host, status`.
  const isSplitByFormat = dimensionRest.length === 1 && effectiveMeasures.length === 1;

  if (!isSplitByFormat) {
    // Already wide (single or multi aggregate). Values = measure columns; fall
    // back to all non-label keys for an all-string result.
    const valueKeys = effectiveMeasures.length > 0 ? effectiveMeasures : rest;
    let out = data;
    if (isTimeSeries && spanMs) {
      const fillCols = valueKeys.map(k => ({ key: k, fill: isZeroFillAgg(k) ? 0 : null }));
      out = densifyTimeBuckets(data, labelKey, spanMs, fillCols);
    }
    return { data: out, labelKey, valueKeys, wasPivoted: false, isTimeSeries, timeKey, spanMs };
  }

  const splitField = dimensionRest[0];
  const valueField = effectiveMeasures[0];
  // Absent split/bucket combos: 0 only for count/sum-class aggregates; a gap
  // (null) for avg/percentile so a quiet bucket doesn't read as "0" (DSH30).
  const fillValue: number | null = isZeroFillAgg(valueField) ? 0 : null;

  const pivotMap = new Map<string, Record<string, unknown>>();
  const allSplitValues = new Set<string>();

  data.forEach((row) => {
    const labelValue = String(row[labelKey] ?? '');
    const splitValue = String(row[splitField] ?? 'unknown');
    const numValue = Number(row[valueField] ?? 0);

    allSplitValues.add(splitValue);

    if (!pivotMap.has(labelValue)) {
      pivotMap.set(labelValue, { [labelKey]: row[labelKey] });
    }

    const dataPoint = pivotMap.get(labelValue)!;
    dataPoint[splitValue] = numValue;
  });

  const splitValueKeys = Array.from(allSplitValues).sort();
  let pivotedData = Array.from(pivotMap.values()).map((point) => {
    splitValueKeys.forEach(key => {
      if (!(key in point)) {
        point[key] = fillValue;
      }
    });
    return point;
  });

  if (isTimeSeries && spanMs) {
    const fillCols = splitValueKeys.map(key => ({ key, fill: fillValue }));
    pivotedData = densifyTimeBuckets(pivotedData, labelKey, spanMs, fillCols);
  }

  return {
    data: pivotedData,
    labelKey,
    valueKeys: splitValueKeys,
    wasPivoted: true,
    isTimeSeries,
    timeKey,
    spanMs,
  };
}

/**
 * Build the CONTRACT 3 drilldown payload from a clicked chart element.
 *
 * `filters` = every group-by field/value pair on the element (numeric group-bys
 * included), i.e. all keys that are not aggregate/series values, the time
 * bucket, or internal. For a time-bucketed click we emit an anchored
 * `[start, start+span]` ISO window instead of a synthetic `time_bucket` filter
 * (DSH27).
 */
function buildDrilldownPayload(
  entry: Record<string, unknown>,
  meta: {
    valueKeys: string[];
    timeKey?: string;
    isTimeSeries: boolean;
    spanMs?: number;
  }
): DrilldownPayload | null {
  // Defense-in-depth: a chart onClick can hand us an out-of-range/undefined datum
  // (e.g. a recharts handler whose arg shape differs by chart type). Never let
  // Object.entries(undefined) throw — just decline the drilldown.
  if (!entry) return null;
  const { valueKeys, timeKey, isTimeSeries, spanMs } = meta;
  const valueSet = new Set(valueKeys);

  let anchorStart: string | undefined;
  let anchorEnd: string | undefined;
  if (isTimeSeries && timeKey && spanMs && spanMs > 0) {
    const startMs = parseTimeMs(entry[timeKey]);
    if (startMs != null) {
      anchorStart = new Date(startMs).toISOString();
      anchorEnd = new Date(startMs + spanMs).toISOString();
    }
  }

  const filters: Array<{ field: string; value: string }> = [];
  for (const [key, value] of Object.entries(entry)) {
    if (key === timeKey) continue;        // conveyed via the anchor window
    if (valueSet.has(key)) continue;      // aggregate / series value, not a filter
    if (key.startsWith('_')) continue;    // internal field
    if (value === null || value === undefined) continue;
    filters.push({ field: key, value: String(value) });
  }

  if (filters.length === 0 && !anchorStart) return null;
  return { filters, anchorStart, anchorEnd };
}

export interface VisualizationRendererProps {
  type: VisualizationType;
  config: VisualizationConfig;
  data: Record<string, unknown>[];
  onDrilldown?: (payload: DrilldownPayload) => void;
  /**
   * Column order from the panel-query response (CONTRACT 1). When present,
   * group-by fields lead and aggregates follow, letting the renderer pick
   * label vs value columns deterministically instead of by `typeof`
   * (DSH6/DSH32/DSH53). Optional — falls back to a name/type heuristic.
   */
  columnOrder?: string[];
}

export function VisualizationRenderer({
  type,
  config,
  data,
  onDrilldown,
  columnOrder,
}: VisualizationRendererProps) {
  switch (type) {
    case 'bar':
      return <BarVisualization data={data} config={config} onDrilldown={onDrilldown} columnOrder={columnOrder} />;
    case 'line':
      return <LineVisualization data={data} config={config} onDrilldown={onDrilldown} columnOrder={columnOrder} />;
    case 'area':
      return <AreaVisualization data={data} config={config} onDrilldown={onDrilldown} columnOrder={columnOrder} />;
    case 'pie':
      return <PieVisualization data={data} config={config} onDrilldown={onDrilldown} columnOrder={columnOrder} />;
    case 'table':
      return <TableVisualization data={data} config={config} onDrilldown={onDrilldown} columnOrder={columnOrder} />;
    case 'single_value':
      return <SingleValueVisualization data={data} config={config} columnOrder={columnOrder} />;
    case 'timeline':
      return <TimelineVisualization data={data} config={config} onDrilldown={onDrilldown} columnOrder={columnOrder} />;
    case 'tree':
      return <DashboardTreeVisualization data={data} config={config} onDrilldown={onDrilldown} />;
    case 'ranked_bar':
      return <DashboardRankedBarChart data={data} onDrilldown={onDrilldown} />;
    case 'transaction':
      return <DashboardTransactionCards data={data} onDrilldown={onDrilldown} />;
    case 'flow':
      return <DashboardFlowVisualization data={data} onDrilldown={onDrilldown} />;
    default:
      return <TableVisualization data={data} config={config} onDrilldown={onDrilldown} columnOrder={columnOrder} />;
  }
}

// Bar Chart Visualization
interface ChartVisualizationProps {
  data: Record<string, unknown>[];
  config: VisualizationConfig;
  onDrilldown?: (payload: DrilldownPayload) => void;
  columnOrder?: string[];
}

function BarVisualization({ data, config, onDrilldown, columnOrder }: ChartVisualizationProps) {
  // Pivot split-by data if needed (e.g., timechart count by action)
  const { data: pivotedData, labelKey, valueKeys, isTimeSeries, timeKey, spanMs } = useMemo(
    () => pivotSplitByData(data, columnOrder),
    [data, columnOrder]
  );

  const isHorizontal = config?.orientation === 'horizontal';

  // Limit data for bar charts - too many bars makes them unreadable
  // Horizontal bars: max 15 (they need vertical space)
  // Vertical bars: max 20 (they need horizontal space)
  const maxBars = isHorizontal ? 15 : 20;
  const isLimited = pivotedData.length > maxBars;
  // Time-bucketed data is ascending by time, so keep the NEWEST maxBars (the
  // current window) rather than silently dropping the most recent buckets;
  // stats bars carry an implicit sort by value, so the leading rows are the
  // genuine top N (DSH29).
  const displayData = !isLimited
    ? pivotedData
    : isTimeSeries
      ? pivotedData.slice(-maxBars)
      : pivotedData.slice(0, maxBars);

  // Calculate dynamic Y-axis width for horizontal charts based on label length
  const maxLabelLength = isHorizontal
    ? Math.max(...displayData.map(d => String(d[labelKey] || '').length))
    : 0;
  const yAxisWidth = isHorizontal ? Math.min(Math.max(maxLabelLength * 7, 80), 200) : 60;

  // Handle click on bar - emits the full drilldown payload (all group-by
  // field/value pairs + an anchored window for time buckets — DSH6/DSH27).
  const handleBarClick = (entry: Record<string, unknown>) => {
    if (!onDrilldown) return;
    const payload = buildDrilldownPayload(entry, { valueKeys, timeKey, isTimeSeries, spanMs });
    if (payload) onDrilldown(payload);
  };

  return (
    <div className="h-full flex flex-col">
      <div className="flex-1">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart
            data={displayData}
            layout={isHorizontal ? 'vertical' : 'horizontal'}
            margin={{ top: 5, right: 20, left: 10, bottom: isHorizontal ? 5 : 20 }}
          >
            {isHorizontal ? (
              <>
                <XAxis
                  type="number"
                  {...AXIS_STYLE}
                  tick={{ fill: '#9ca3af', fontFamily: 'var(--font-mono)' }}
                  tickFormatter={formatCompactNumber}
                />
                <YAxis
                  dataKey={labelKey}
                  type="category"
                  {...AXIS_STYLE}
                  width={yAxisWidth}
                  tick={{ fill: '#9ca3af', fontSize: 10, fontFamily: 'var(--font-mono)' }}
                  tickFormatter={(value) => String(value).length > 25 ? String(value).substring(0, 22) + '...' : String(value)}
                />
              </>
            ) : (
              <>
                <XAxis
                  dataKey={labelKey}
                  {...AXIS_STYLE}
                  tick={{ fill: '#9ca3af', fontFamily: 'var(--font-mono)' }}
                  interval="preserveStartEnd"
                  angle={-30}
                  textAnchor="end"
                  height={56}
                />
                <YAxis
                  {...AXIS_STYLE}
                  tick={{ fill: '#9ca3af', fontFamily: 'var(--font-mono)' }}
                  tickFormatter={formatCompactNumber}
                  width={56}
                />
              </>
            )}
            <Tooltip contentStyle={TOOLTIP_STYLE} labelStyle={TOOLTIP_LABEL_STYLE} cursor={false} />
            {valueKeys.length > 1 && <Legend wrapperStyle={{ color: '#9ca3af', fontFamily: 'var(--font-mono)', fontSize: '11px' }} />}
            {valueKeys.map((key, i) => (
              <Bar
                key={key}
                dataKey={key}
                fill={CHART_COLORS[i % CHART_COLORS.length]}
                radius={isHorizontal ? [0, 4, 4, 0] : [4, 4, 0, 0]}
                stackId={config?.stacked ? 'stack' : undefined}
                cursor={onDrilldown ? 'pointer' : 'default'}
                // recharts v3 dropped `activePayload` from the chart-level onClick,
                // so read the clicked datum element-level via its index (the same
                // pattern the Pie uses, which kept working across the upgrade). This
                // is what actually fires drilldown for Bar charts (DSH27).
                onClick={(_, index) => handleBarClick(displayData[index])}
              />
            ))}
          </BarChart>
        </ResponsiveContainer>
      </div>
      {isLimited && (
        <div className="py-1 text-center text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground">
          {isTimeSeries
            ? `Showing latest ${maxBars} of ${pivotedData.length} buckets`
            : `Showing top ${maxBars} of ${pivotedData.length} results`}
        </div>
      )}
    </div>
  );
}

// Line Chart Visualization
function LineVisualization({ data, config, onDrilldown, columnOrder }: ChartVisualizationProps) {
  // Pivot split-by data if needed (e.g., timechart count by action)
  const { data: chartData, labelKey, valueKeys, isTimeSeries, timeKey, spanMs } = useMemo(
    () => pivotSplitByData(data, columnOrder),
    [data, columnOrder]
  );

  // Handle click on line point - emits the full drilldown payload (DSH6/DSH27).
  const handlePointClick = (entry: Record<string, unknown>) => {
    if (!onDrilldown) return;
    const payload = buildDrilldownPayload(entry, { valueKeys, timeKey, isTimeSeries, spanMs });
    if (payload) onDrilldown(payload);
  };

  return (
    <ResponsiveContainer width="100%" height="100%">
      <LineChart
        data={chartData}
        margin={{ top: 5, right: 20, left: 10, bottom: 5 }}
      >
        <XAxis
          dataKey={labelKey}
          {...AXIS_STYLE}
          tick={{ fill: '#9ca3af', fontFamily: 'var(--font-mono)' }}
          interval="preserveStartEnd"
          minTickGap={32}
        />
        <YAxis
          {...AXIS_STYLE}
          tick={{ fill: '#9ca3af', fontFamily: 'var(--font-mono)' }}
          tickFormatter={formatCompactNumber}
          width={56}
        />
        <Tooltip contentStyle={TOOLTIP_STYLE} labelStyle={TOOLTIP_LABEL_STYLE} />
        {valueKeys.length > 1 && <Legend wrapperStyle={{ color: '#9ca3af', fontFamily: 'var(--font-mono)', fontSize: '11px' }} />}
        {valueKeys.map((key, i) => (
          <Line
            key={key}
            type={config?.smooth ? 'monotone' : 'linear'}
            dataKey={key}
            stroke={CHART_COLORS[i % CHART_COLORS.length]}
            strokeWidth={2}
            dot={config?.showPoints !== false}
            activeDot={{
              r: 6,
              cursor: onDrilldown ? 'pointer' : 'default',
              // recharts v3: Line/Area have no element-level item-click dispatch, so
              // the drilldown target is the active dot. Empirically recharts invokes
              // this as (event, dotProps) — the datum index is on the 2nd arg
              // (dotProps.index). Read it robustly (fall back to the 1st arg) and
              // guard so a stray call no-ops (DSH27, verified in-browser).
              onClick: (...args: unknown[]) => {
                // recharts v3's activeDot onClick arg shape is path/version-dependent
                // (empirically the datum index rides on dotProps as the 2nd arg, but
                // some code paths put the props first). Scan the args for the first
                // numeric `.index` so drilldown fires regardless of arg order.
                const idx = args
                  .map((x) => (x as { index?: number } | undefined)?.index)
                  .find((n): n is number => typeof n === 'number');
                if (typeof idx === 'number') handlePointClick(chartData[idx]);
              },
            }}
          />
        ))}
      </LineChart>
    </ResponsiveContainer>
  );
}

// Area Chart Visualization
function AreaVisualization({ data, config, onDrilldown, columnOrder }: ChartVisualizationProps) {
  // Pivot split-by data if needed (e.g., timechart count by action)
  const { data: chartData, labelKey, valueKeys, isTimeSeries, timeKey, spanMs } = useMemo(
    () => pivotSplitByData(data, columnOrder),
    [data, columnOrder]
  );

  // Handle click on area point - emits the full drilldown payload (DSH6/DSH27).
  const handlePointClick = (entry: Record<string, unknown>) => {
    if (!onDrilldown) return;
    const payload = buildDrilldownPayload(entry, { valueKeys, timeKey, isTimeSeries, spanMs });
    if (payload) onDrilldown(payload);
  };

  return (
    <ResponsiveContainer width="100%" height="100%">
      <AreaChart
        data={chartData}
        margin={{ top: 5, right: 20, left: 10, bottom: 5 }}
      >
        <XAxis
          dataKey={labelKey}
          {...AXIS_STYLE}
          tick={{ fill: '#9ca3af', fontFamily: 'var(--font-mono)' }}
          interval="preserveStartEnd"
          minTickGap={32}
        />
        <YAxis
          {...AXIS_STYLE}
          tick={{ fill: '#9ca3af', fontFamily: 'var(--font-mono)' }}
          tickFormatter={formatCompactNumber}
          width={56}
        />
        <Tooltip contentStyle={TOOLTIP_STYLE} labelStyle={TOOLTIP_LABEL_STYLE} />
        {valueKeys.length > 1 && <Legend wrapperStyle={{ color: '#9ca3af', fontFamily: 'var(--font-mono)', fontSize: '11px' }} />}
        {valueKeys.map((key, i) => (
          <Area
            key={key}
            type={config?.smooth ? 'monotone' : 'linear'}
            dataKey={key}
            stroke={CHART_COLORS[i % CHART_COLORS.length]}
            fill={CHART_COLORS[i % CHART_COLORS.length]}
            fillOpacity={config?.fillOpacity ?? 0.3}
            activeDot={{
              r: 6,
              cursor: onDrilldown ? 'pointer' : 'default',
              // recharts v3: see LineVisualization — the active-dot onClick is invoked
              // (event, dotProps); the datum index is on the 2nd arg (DSH27).
              onClick: (...args: unknown[]) => {
                // recharts v3's activeDot onClick arg shape is path/version-dependent
                // (empirically the datum index rides on dotProps as the 2nd arg, but
                // some code paths put the props first). Scan the args for the first
                // numeric `.index` so drilldown fires regardless of arg order.
                const idx = args
                  .map((x) => (x as { index?: number } | undefined)?.index)
                  .find((n): n is number => typeof n === 'number');
                if (typeof idx === 'number') handlePointClick(chartData[idx]);
              },
            }}
          />
        ))}
      </AreaChart>
    </ResponsiveContainer>
  );
}

// Pie Chart Visualization
function PieVisualization({ data, config, onDrilldown, columnOrder }: ChartVisualizationProps) {
  // Label = the group-by category (a label even when numeric, e.g. dest_port),
  // value = the aggregate that sizes the slices. Chosen from column_order/roles,
  // NOT by typeof, so slices aren't sized by the port number and aren't named
  // with an aggregate value (DSH6/DSH32).
  const { keys, labelKey, valueKeys, timeKey, isTimeSeries, spanMs } = classifyColumns(data, columnOrder);
  // Prefer an explicit `count` aggregate for slice size (the usual "X by
  // category" pie); otherwise the first aggregate column.
  const valueKey =
    valueKeys.find(k => k.toLowerCase() === 'count') ??
    valueKeys[0] ??
    keys.find(k => k !== labelKey) ??
    keys[0];

  // Calculate total for center display
  const total = data.reduce((sum, item) => sum + (Number(item[valueKey]) || 0), 0);

  // Check if labels should be shown (default to false for clean donut look)
  const showLabels = config?.showLabels === true;

  // Handle click on pie slice - emits the full drilldown payload (DSH6/DSH27).
  const handleSliceClick = (entry: Record<string, unknown>) => {
    if (!onDrilldown) return;
    const payload = buildDrilldownPayload(entry, { valueKeys, timeKey, isTimeSeries, spanMs });
    if (payload) onDrilldown(payload);
  };

  // Custom label renderer for outside labels
  const renderLabel = showLabels ? (props: {
    cx?: number;
    cy?: number;
    midAngle?: number;
    outerRadius?: number;
    name?: string;
    percent?: number;
  }) => {
    const { cx = 0, cy = 0, midAngle = 0, outerRadius = 0, name = '', percent = 0 } = props;
    const RADIAN = Math.PI / 180;
    const radius = outerRadius * 1.2;
    const x = cx + radius * Math.cos(-midAngle * RADIAN);
    const y = cy + radius * Math.sin(-midAngle * RADIAN);

    return (
      <text
        x={x}
        y={y}
        fill="#f3f4f6"
        textAnchor={x > cx ? 'start' : 'end'}
        dominantBaseline="central"
        style={{ fontSize: '11px' }}
      >
        {`${name || 'null'} (${(percent * 100).toFixed(0)}%)`}
      </text>
    );
  } : false;

  return (
    <ResponsiveContainer width="100%" height="100%">
      <PieChart>
        <Pie
          data={data}
          dataKey={valueKey}
          nameKey={labelKey}
          cx="50%"
          cy="50%"
          innerRadius="60%"
          outerRadius={showLabels ? "70%" : "85%"}
          paddingAngle={0}
          strokeWidth={0}
          label={renderLabel}
          labelLine={showLabels}
          onClick={(_, index) => handleSliceClick(data[index])}
          cursor={onDrilldown ? 'pointer' : 'default'}
        >
          {data.map((_, i) => (
            <Cell key={i} fill={CHART_COLORS[i % CHART_COLORS.length]} stroke="none" />
          ))}
        </Pie>
        <Tooltip 
          contentStyle={TOOLTIP_STYLE} 
          itemStyle={{ color: '#f3f4f6', fontFamily: 'var(--font-mono)', fontSize: '11px' }}
          formatter={(value, name) => {
            const coerced = typeof value === 'number' ? value : Number(value);
            const n = Number.isFinite(coerced) ? coerced : 0;
            // Guard against an all-zero pie (total === 0) → n/0 = NaN%.
            const pct = total > 0 ? ((n / total) * 100).toFixed(1) : '0.0';
            return [
              `${n.toLocaleString()} (${pct}%)`,
              (typeof name === 'string' ? name : String(name ?? '')) || 'null',
            ];
          }}
        />
        {/* Center text showing total */}
        <text
          x="50%"
          y="46%"
          textAnchor="middle"
          dominantBaseline="middle"
          style={{ fontSize: '24px', fontWeight: 'bold', fill: '#f3f4f6', fontFamily: 'var(--font-mono)' }}
        >
          {formatCompactNumber(total)}
        </text>
        <text
          x="50%"
          y="56%"
          textAnchor="middle"
          dominantBaseline="middle"
          style={{ fontSize: '11px', fill: '#9ca3af', fontFamily: 'var(--font-mono)', letterSpacing: '0.08em', textTransform: 'uppercase' }}
        >
          Total
        </text>
      </PieChart>
    </ResponsiveContainer>
  );
}

// Table Visualization with sorting and pagination
function TableVisualization({ data, config, onDrilldown, columnOrder }: ChartVisualizationProps) {
  const [sortField, setSortField] = useState<string | null>(null);
  const [sortDirection, setSortDirection] = useState<'asc' | 'desc'>('asc');
  const [currentPage, setCurrentPage] = useState(0);

  const pageSize = config?.pageSize || 10;

  // Column roles for drilldown (group-by vs aggregate) — column_order-aware.
  const roles = useMemo(() => classifyColumns(data, columnOrder), [data, columnOrder]);

  // Generate columns from config or data. Without an explicit column config, use
  // the query/response column order so panel tables match the same query on
  // Search instead of serde_json's alphabetical key order (DSH53).
  const columns: TableColumnConfig[] = useMemo(() => {
    if (config?.columns && config.columns.length > 0) {
      return config.columns;
    }
    return orderedColumns(data[0] || {}, columnOrder).map(key => ({
      field: key,
      label: key,
      sortable: true,
    }));
  }, [config?.columns, data, columnOrder]);

  // Sort data
  const sortedData = useMemo(() => {
    if (!sortField) return data;
    
    return [...data].sort((a, b) => {
      const aVal = a[sortField];
      const bVal = b[sortField];
      
      if (aVal === bVal) return 0;
      if (aVal === null || aVal === undefined) return 1;
      if (bVal === null || bVal === undefined) return -1;

      // Numeric-aware: a numeric group-by (e.g. dest_port) can arrive as a JSON
      // number OR a numeric string; raw `<` would sort those lexicographically
      // ("1024" < "22" < "443" < "80"). Compare numerically when both coerce to a
      // finite number, else fall back to locale string compare.
      const aNum = typeof aVal === 'number' ? aVal : Number(aVal);
      const bNum = typeof bVal === 'number' ? bVal : Number(bVal);
      const bothNumeric =
        aVal !== '' && bVal !== '' && Number.isFinite(aNum) && Number.isFinite(bNum);
      const comparison = bothNumeric
        ? aNum - bNum
        : String(aVal).localeCompare(String(bVal));
      return sortDirection === 'asc' ? comparison : -comparison;
    });
  }, [data, sortField, sortDirection]);

  // Paginate data
  const paginatedData = useMemo(() => {
    const start = currentPage * pageSize;
    return sortedData.slice(start, start + pageSize);
  }, [sortedData, currentPage, pageSize]);

  const totalPages = Math.ceil(data.length / pageSize);

  const handleSort = (field: string) => {
    if (sortField === field) {
      setSortDirection(prev => prev === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('asc');
    }
  };

  // Handle click on table row - emits ALL group-by field/value pairs (numeric
  // group-bys included, aggregates and the time bucket excluded). Tables don't
  // anchor a bucket window; they navigate with the dashboard time range (DSH27).
  const handleRowClick = (row: Record<string, unknown>) => {
    if (!onDrilldown) return;
    const payload = buildDrilldownPayload(row, {
      valueKeys: roles.valueKeys,
      timeKey: roles.timeKey,
      isTimeSeries: false,
      spanMs: undefined,
    });
    if (payload) onDrilldown(payload);
  };

  return (
    <div className="h-full flex flex-col">
      <div className="flex-1 overflow-auto">
        <table className="w-full text-sm">
          <thead className="sticky top-0 bg-card">
            <tr className="border-b border-border">
              {columns.map((col) => (
                <th 
                  key={col.field} 
                  className={`p-2 text-left text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground font-medium ${
                    col.sortable ? 'cursor-pointer hover:text-primary' : ''
                  }`}
                  style={col.width ? { width: col.width } : undefined}
                  onClick={() => col.sortable && handleSort(col.field)}
                >
                  <div className="flex items-center gap-1">
                    {col.label}
                    {col.sortable && sortField === col.field && (
                      sortDirection === 'asc' 
                        ? <ChevronUp className="w-3 h-3" />
                        : <ChevronDown className="w-3 h-3" />
                    )}
                  </div>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {paginatedData.map((row, i) => (
              <tr 
                key={i} 
                className={`border-b border-border hover:bg-accent/50 ${
                  onDrilldown ? 'cursor-pointer' : ''
                }`}
                onClick={() => handleRowClick(row)}
              >
                {columns.map((col) => (
                  <td key={col.field} className="p-2 font-mono text-[13px] text-foreground">
                    {formatCellValue(row[col.field])}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      
      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between pt-2 border-t border-border mt-2">
          <span className="text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground">
            Showing {currentPage * pageSize + 1}-{Math.min((currentPage + 1) * pageSize, data.length)} of {data.length}
          </span>
          <div className="flex items-center gap-1">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setCurrentPage(p => Math.max(0, p - 1))}
              disabled={currentPage === 0}
              className="h-7 w-7 p-0 text-muted-foreground"
            >
              <ChevronLeft className="w-4 h-4" />
            </Button>
            <span className="px-2 text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground">
              {currentPage + 1} / {totalPages}
            </span>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setCurrentPage(p => Math.min(totalPages - 1, p + 1))}
              disabled={currentPage >= totalPages - 1}
              className="h-7 w-7 p-0 text-muted-foreground"
            >
              <ChevronRight className="w-4 h-4" />
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

// Single Value Metric Visualization
interface SingleValueProps {
  data: Record<string, unknown>[];
  config: VisualizationConfig;
  columnOrder?: string[];
}

function SingleValueVisualization({ data, config, columnOrder }: SingleValueProps) {
  const keys = orderedColumns(data[0] || {}, columnOrder);
  const valueKey = keys.find(k => typeof data[0]?.[k] === 'number') || keys[0];

  // For an ascending time series the newest bucket is LAST, so the current value
  // is the last row and the previous is the second-to-last — not data[0] (the
  // oldest bucket) trended against data[1] with an inverted arrow (DSH31).
  const isTimeSeries = keys.some(isTimeLikeKey) && data.length > 1;
  const currentIdx = isTimeSeries ? data.length - 1 : 0;
  const previousIdx = isTimeSeries ? data.length - 2 : 1;
  const value = data[currentIdx]?.[valueKey];

  // Calculate trend if we have multiple data points
  const trend = useMemo(() => {
    if (!config?.showTrend || data.length < 2) return null;

    const current = Number(data[currentIdx]?.[valueKey]) || 0;
    const previous = Number(data[previousIdx]?.[valueKey]) || 0;

    if (previous === 0) return null;

    const percentChange = ((current - previous) / previous) * 100;
    return {
      direction: percentChange > 0 ? 'up' : percentChange < 0 ? 'down' : 'flat',
      value: Math.abs(percentChange).toFixed(1),
    };
  }, [data, valueKey, config?.showTrend, currentIdx, previousIdx]);

  // Determine color based on thresholds
  const getColor = (val: unknown): string => {
    if (!config?.thresholds || typeof val !== 'number') {
      return 'text-foreground';
    }
    
    // Sort thresholds descending
    const sortedThresholds = [...config.thresholds].sort((a, b) => b.value - a.value);
    
    for (const threshold of sortedThresholds) {
      if (val >= threshold.value) {
        // Handle both direct color classes and color names
        if (threshold.color.startsWith('text-') || threshold.color.startsWith('#')) {
          return threshold.color;
        }
        return `text-${threshold.color}-500`;
      }
    }
    
    return 'text-foreground';
  };

  const colorClass = getColor(value);
  const displayValue = typeof value === 'number'
    ? formatCompactNumber(value)
    : String(value ?? '-');

  return (
    <div className="h-full flex flex-col items-center justify-center">
      <div className={`font-mono text-4xl font-bold ${colorClass}`}>
        {displayValue}
        {config?.unit && (
          <span className="ml-1 text-lg text-muted-foreground">{config.unit}</span>
        )}
      </div>
      
      {trend && (
        <div className={`mt-2 flex items-center gap-1 font-mono text-xs uppercase tracking-[0.12em] ${
          trend.direction === 'up' ? 'text-green-400' :
          trend.direction === 'down' ? 'text-red-400' :
          'text-muted-foreground'
        }`}>
          {trend.direction === 'up' && <TrendingUp className="w-4 h-4" />}
          {trend.direction === 'down' && <TrendingDown className="w-4 h-4" />}
          {trend.direction === 'flat' && <Minus className="w-4 h-4" />}
          <span>{trend.value}%</span>
        </div>
      )}
    </div>
  );
}

// Timeline Visualization (essentially an area chart with time on X axis)
function TimelineVisualization({ data, config, onDrilldown, columnOrder }: ChartVisualizationProps) {
  // Timeline is an area chart with specific styling for time-based data
  return (
    <AreaVisualization
      data={data}
      config={{
        ...config,
        fillOpacity: config?.fillOpacity ?? 0.5,
        smooth: config?.smooth ?? true,
      }}
      onDrilldown={onDrilldown}
      columnOrder={columnOrder}
    />
  );
}

// Numbers render unformatted (no thousands separators) so dest_port / src_port /
// numeric IDs match search-result rendering in PaginatedTable.formatCellValue.
function formatCellValue(value: unknown): string {
  if (value === null || value === undefined) {
    return '-';
  }
  if (typeof value === 'boolean') {
    return value ? 'Yes' : 'No';
  }
  if (value instanceof Date) {
    return value.toLocaleString();
  }
  if (typeof value === 'object') {
    return JSON.stringify(value);
  }
  return String(value);
}

// Dashboard wrapper for TreeVisualization
// Adapts the search tree component to work with dashboard data format
interface DashboardTreeProps {
  data: Record<string, unknown>[];
  config: VisualizationConfig;
  onDrilldown?: (payload: DrilldownPayload) => void;
}

function DashboardTreeVisualization({ data, config, onDrilldown }: DashboardTreeProps) {
  // Tree config from visualization config (TreeConfig uses snake_case)
  const treeConfig = {
    parent_field: config?.parentField || 'parent_id',
    child_field: config?.childField || 'id',
    label_field: config?.labelField || 'name',
  };

  // Build tree nodes from flat data
  const nodes = useMemo((): TreeNode[] => {
    if (!data.length) return [];

    const { parent_field, child_field, label_field } = treeConfig;

    const nodeMap = new Map<string, TreeNode>();
    const rootNodes: TreeNode[] = [];

    // First pass: create all nodes
    for (const row of data) {
      const id = String(row[child_field] ?? '');
      const label = String(row[label_field] ?? id);

      nodeMap.set(id, {
        id,
        label,
        _data: row,
        children: [],
      });
    }

    // Second pass: build tree structure
    for (const row of data) {
      const id = String(row[child_field] ?? '');
      const parentId = row[parent_field] != null ? String(row[parent_field]) : null;
      const node = nodeMap.get(id);

      if (!node) continue;

      if (parentId && nodeMap.has(parentId)) {
        const parent = nodeMap.get(parentId)!;
        parent.children = parent.children || [];
        parent.children.push(node);
      } else {
        // No parent or parent not in data = root node
        rootNodes.push(node);
      }
    }

    return rootNodes;
  }, [data, treeConfig]);

  const handleFilter = onDrilldown
    ? (field: string, value: string) => {
        onDrilldown({ filters: [{ field, value }] });
      }
    : undefined;

  return (
    <div className="h-full overflow-auto">
      <TreeVisualization
        nodes={nodes}
        config={treeConfig}
        onFilter={handleFilter}
      />
    </div>
  );
}

// Dashboard wrapper for RankedBarChart
interface DashboardRankedBarProps {
  data: Record<string, unknown>[];
  onDrilldown?: (payload: DrilldownPayload) => void;
}

function DashboardRankedBarChart({ data, onDrilldown }: DashboardRankedBarProps) {
  // Convert dashboard data format to search result format
  const searchResults = data.map((row, idx) => ({
    id: String(idx),
    timestamp: new Date(),
    source: 'dashboard',
    fields: row,
  }));

  const handleDrilldown = onDrilldown
    ? (filters: Record<string, unknown>) => {
        // Emit ALL field/value pairs (not just the first), skipping internal
        // keys and nulls, so grouped drilldowns keep every dimension (DSH27).
        const pairs = Object.entries(filters)
          .filter(([k, v]) => !k.startsWith('_') && v !== null && v !== undefined)
          .map(([field, value]) => ({ field, value: String(value) }));
        if (pairs.length > 0) onDrilldown({ filters: pairs });
      }
    : undefined;

  return (
    <div className="h-full overflow-auto">
      <RankedBarChart results={searchResults} onDrilldown={handleDrilldown} />
    </div>
  );
}

// Dashboard wrapper for TransactionCards
interface DashboardTransactionProps {
  data: Record<string, unknown>[];
  onDrilldown?: (payload: DrilldownPayload) => void;
}

function DashboardTransactionCards({ data, onDrilldown }: DashboardTransactionProps) {
  // Convert dashboard data format to search result format
  const searchResults = data.map((row, idx) => ({
    id: String(idx),
    timestamp: new Date(),
    source: 'dashboard',
    fields: row,
  }));

  const handleDrilldown = onDrilldown
    ? (filters: Record<string, unknown>) => {
        // Emit ALL field/value pairs (not just the first), skipping internal
        // keys and nulls, so grouped drilldowns keep every dimension (DSH27).
        const pairs = Object.entries(filters)
          .filter(([k, v]) => !k.startsWith('_') && v !== null && v !== undefined)
          .map(([field, value]) => ({ field, value: String(value) }));
        if (pairs.length > 0) onDrilldown({ filters: pairs });
      }
    : undefined;

  return (
    <div className="h-full overflow-auto">
      <TransactionCards
        results={searchResults}
        onDrilldown={handleDrilldown}
      />
    </div>
  );
}

// Dashboard wrapper for FlowVisualization
interface DashboardFlowProps {
  data: Record<string, unknown>[];
  onDrilldown?: (payload: DrilldownPayload) => void;
}

function DashboardFlowVisualization({ data, onDrilldown }: DashboardFlowProps) {
  // Convert dashboard data format to search result format
  const searchResults = data.map((row, idx) => ({
    id: String(idx),
    timestamp: new Date(),
    source: 'dashboard',
    fields: row,
  }));

  const handleDrilldown = onDrilldown
    ? (filters: Record<string, unknown>) => {
        // Emit ALL field/value pairs (not just the first), skipping internal
        // keys and nulls, so grouped drilldowns keep every dimension (DSH27).
        const pairs = Object.entries(filters)
          .filter(([k, v]) => !k.startsWith('_') && v !== null && v !== undefined)
          .map(([field, value]) => ({ field, value: String(value) }));
        if (pairs.length > 0) onDrilldown({ filters: pairs });
      }
    : undefined;

  return (
    <div className="h-full overflow-auto">
      <FlowVisualization results={searchResults} onDrilldown={handleDrilldown} />
    </div>
  );
}

export default VisualizationRenderer;
