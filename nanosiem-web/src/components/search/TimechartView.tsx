// SPDX-License-Identifier: AGPL-3.0-or-later

import React from 'react';
import { formatInTimeZone } from 'date-fns-tz';
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { Activity, ChevronDown, ChevronRight, Clock, Download, Grid3x3 } from 'lucide-react';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { cn } from '@/lib/utils';

interface SearchResult {
  id: string;
  timestamp: Date;
  source: string;
  fields: Record<string, unknown>;
}

interface TimechartViewProps {
  results: SearchResult[];
  query?: string;
  onSetQuery?: (query: string) => void;
  onDrilldown?: (filters: Record<string, unknown>) => void;
  fieldsCollapsed?: boolean;
  fieldsCount?: number;
  onExpandFields?: () => void;
}

// ───────────────────────────── helpers ─────────────────────────────

function formatY(value: number): string {
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(value % 1_000_000 === 0 ? 0 : 1)}M`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(value % 1_000 === 0 ? 0 : 1)}k`;
  return Math.round(value).toString();
}

function parseTimeBucket(value: unknown): number | null {
  if (typeof value === 'number') return value;
  if (typeof value === 'string') {
    const d = new Date(value);
    if (!isNaN(d.getTime())) return d.getTime();
  }
  return null;
}

function formatBucketTime(ts: number): string {
  try {
    return formatInTimeZone(new Date(ts), 'UTC', 'MM/dd HH:mm');
  } catch {
    return String(ts);
  }
}

/**
 * Distinct per-series palette so each series reads apart rather
 * than blending into a cyan ramp. First slot is brand cyan; remaining slots
 * rotate through distinct hues at a consistent perceptual lightness. Tuned
 * so adjacent series don't collide.
 */
const SERIES_PALETTE = [
  '#5EE7F0', // cyan (brand)
  '#FB7185', // rose
  '#FBBF24', // amber
  '#A78BFA', // violet
  '#34D399', // emerald
  '#60A5FA', // blue
  '#FB923C', // orange
  '#F472B6', // pink
  '#22D3EE', // sky
  '#C084FC', // purple
];
const OTHER_COLOR = '#71717A'; // zinc-500

function seriesColor(i: number, isOther: boolean): string {
  if (isOther) return OTHER_COLOR;
  return SERIES_PALETTE[i % SERIES_PALETTE.length];
}

type Span = { n: number; unit: 's' | 'm' | 'h' | 'd' };

function parseSpan(query: string | undefined): Span {
  const m = query?.match(/\|\s*timechart[^|]*?\bspan\s*=\s*(\d+)([smhd])/i);
  if (m) return { n: parseInt(m[1], 10), unit: m[2].toLowerCase() as Span['unit'] };
  return { n: 1, unit: 'h' };
}

function setSpanInQuery(query: string, span: string): string {
  // Replace existing span in the | timechart clause, or inject one.
  if (/\|\s*timechart[^|]*?\bspan\s*=\s*\d+[smhd]/i.test(query)) {
    return query.replace(/(\|\s*timechart[^|]*?\bspan\s*=\s*)\d+[smhd]/i, `$1${span}`);
  }
  return query.replace(/\|\s*timechart\s+/i, `| timechart span=${span} `);
}

function parseTimechartHeader(query: string | undefined): { aggLabel: string; by: string | null } {
  if (!query) return { aggLabel: 'count', by: null };
  const m = query.match(/\|\s*timechart\b[^|]*/i);
  if (!m) return { aggLabel: 'count', by: null };
  const clause = m[0];
  const aggM = clause.match(/\b(?!span\b)(\w+)\s*(?:\(\s*([^)]*)\s*\))?(?=\s*(?:by\b|$|,))/i);
  const byM = clause.match(/\bby\s+([A-Za-z_][\w.]*)/i);
  const agg = aggM ? aggM[1] : 'count';
  const aggField = aggM?.[2]?.trim();
  const aggLabel = aggField ? `${agg}(${aggField})` : agg;
  return { aggLabel, by: byM?.[1] ?? null };
}

// ────────────────────────── data transform ─────────────────────────

interface TransformedData {
  rows: Array<Record<string, unknown>>;
  seriesKeys: string[];     // top 10 + optional "Other"
  seriesTotals: Record<string, number>;
  timeKey: string;
  otherKeys: string[];      // series folded into "Other"
}

const TOP_N = 10;

function transformResults(results: SearchResult[]): TransformedData {
  if (!results.length) {
    return { rows: [], seriesKeys: [], seriesTotals: {}, timeKey: 'time_bucket', otherKeys: [] };
  }

  const sample = results[0]?.fields ?? {};
  let timeKey = 'time_bucket';
  if (!('time_bucket' in sample)) {
    const t = Object.keys(sample).find((k) => k.includes('time') || k.includes('bucket'));
    if (t) timeKey = t;
  }

  const numericKeys = Object.keys(sample).filter((k) => k !== timeKey && typeof sample[k] === 'number');
  const stringKeys = Object.keys(sample).filter((k) => k !== timeKey && typeof sample[k] === 'string');

  // Split-by pattern: pivot on the string column(s)
  const isSplitBy = stringKeys.length >= 1 && numericKeys.length >= 1;

  const bucketMap = new Map<number, Record<string, unknown>>();
  const totalsMap = new Map<string, number>();

  if (isSplitBy) {
    const valueField = numericKeys[0];
    for (const r of results) {
      const f = r.fields || {};
      const ts = parseTimeBucket(f[timeKey]);
      if (ts == null) continue;
      const key = stringKeys.length === 1
        ? String(f[stringKeys[0]] ?? 'unknown')
        : stringKeys.map((k) => String(f[k] ?? '')).join(' / ');
      const v = Number(f[valueField] ?? 0);
      totalsMap.set(key, (totalsMap.get(key) ?? 0) + v);
      let row = bucketMap.get(ts);
      if (!row) {
        row = { [timeKey]: f[timeKey], timestamp: ts };
        bucketMap.set(ts, row);
      }
      row[key] = ((row[key] as number | undefined) ?? 0) + v;
    }
  } else {
    for (const r of results) {
      const f = r.fields || {};
      const ts = parseTimeBucket(f[timeKey]);
      if (ts == null) continue;
      const row: Record<string, unknown> = { [timeKey]: f[timeKey], timestamp: ts };
      for (const k of numericKeys) {
        const v = Number(f[k] ?? 0);
        row[k] = v;
        totalsMap.set(k, (totalsMap.get(k) ?? 0) + v);
      }
      bucketMap.set(ts, row);
    }
  }

  const sortedByTotal = Array.from(totalsMap.entries()).sort((a, b) => b[1] - a[1]);
  const topKeys = sortedByTotal.slice(0, TOP_N).map((x) => x[0]);
  const otherKeys = sortedByTotal.slice(TOP_N).map((x) => x[0]);

  const seriesKeys = otherKeys.length ? [...topKeys, 'Other'] : topKeys;

  // Fold `Other` into each bucket row, fill missing with 0
  const rows = Array.from(bucketMap.values())
    .map((row) => {
      let other = 0;
      for (const k of otherKeys) {
        other += Number(row[k] ?? 0);
      }
      for (const k of topKeys) if (row[k] == null) row[k] = 0;
      if (otherKeys.length) row.Other = other;
      return row;
    })
    .sort((a, b) => (a.timestamp as number) - (b.timestamp as number));

  const seriesTotals: Record<string, number> = {};
  for (const k of topKeys) seriesTotals[k] = totalsMap.get(k) ?? 0;
  if (otherKeys.length) {
    seriesTotals.Other = otherKeys.reduce((s, k) => s + (totalsMap.get(k) ?? 0), 0);
  }

  return { rows, seriesKeys, seriesTotals, timeKey, otherKeys };
}

// ───────────────────────────── tooltip ─────────────────────────────

interface RechartsTooltipProps {
  active?: boolean;
  payload?: Array<{ name: string; value: number; color: string; dataKey: string }>;
  label?: string | number;
}

function ChartTooltip({ active, payload, label }: RechartsTooltipProps) {
  if (!active || !payload?.length) return null;
  let timeLabel = '';
  if (typeof label === 'number') {
    try { timeLabel = formatInTimeZone(new Date(label), 'UTC', 'MM/dd HH:mm'); }
    catch { timeLabel = String(label); }
  } else if (typeof label === 'string') {
    const d = new Date(label);
    timeLabel = !isNaN(d.getTime()) ? formatInTimeZone(d, 'UTC', 'MM/dd HH:mm') : label;
  }

  const entries = [...payload]
    .filter((e) => (e.value ?? 0) > 0)
    .sort((a, b) => b.value - a.value)
    .slice(0, 10);
  const total = payload.reduce((s, e) => s + (e.value ?? 0), 0);

  return (
    <div className="bg-card/95 backdrop-blur border border-border rounded-md shadow-lg text-[11px] min-w-[240px]">
      <div className="px-2.5 py-1.5 border-b border-border font-mono text-foreground tracking-wide">
        {timeLabel}
      </div>
      <div className="py-1">
        {entries.map((e) => (
          <div key={e.dataKey} className="flex items-center gap-2 px-2.5 py-0.5">
            <span className="w-2 h-2 rounded-sm shrink-0" style={{ background: e.color }} />
            <span className="font-mono text-foreground/85 truncate flex-1">{e.name}</span>
            <span className="font-mono text-foreground tabular-nums">{formatY(e.value)}</span>
          </div>
        ))}
      </div>
      <div className="px-2.5 py-1.5 border-t border-border flex items-center justify-between font-mono text-muted-foreground">
        <span>Total</span>
        <span className="text-foreground tabular-nums">{formatY(total)}</span>
      </div>
    </div>
  );
}

// ───────────────────────────── legend ──────────────────────────────

interface LegendProps {
  seriesKeys: string[];
  seriesTotals: Record<string, number>;
  rows: Array<Record<string, unknown>>;
  muted: Set<string>;
  isolated: string | null;
  onToggleMute: (k: string) => void;
  onIsolate: (k: string) => void;
  colorFor: (i: number, k: string) => string;
}

function Sparkline({ values, color, dim }: { values: number[]; color: string; dim: boolean }) {
  if (!values.length) return null;
  const max = Math.max(1, ...values);
  const W = 44, H = 14;
  const d = values
    .map((v, i) => `${((i / Math.max(1, values.length - 1)) * W).toFixed(1)},${(H - (v / max) * H).toFixed(1)}`)
    .join(' L ');
  return (
    <svg width={W} height={H} className="shrink-0">
      <path d={`M ${d}`} fill="none" stroke={color} strokeWidth={1} strokeOpacity={dim ? 0.5 : 1} />
    </svg>
  );
}

function Legend({ seriesKeys, seriesTotals, rows, muted, isolated, onToggleMute, onIsolate, colorFor }: LegendProps) {
  const [filter, setFilter] = React.useState('');
  const items = seriesKeys
    .map((k, i) => ({ k, i, total: seriesTotals[k] ?? 0 }))
    .filter((x) => !filter || x.k.toLowerCase().includes(filter.toLowerCase()));

  return (
    <div className="border-l border-border flex flex-col min-h-0 bg-muted/30">
      <div className="px-2.5 pt-2 pb-1.5 border-b border-border">
        <input
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="Filter series"
          className="w-full bg-transparent outline-none text-[11px] px-2 py-1 rounded border border-border focus:border-primary/60 placeholder:text-muted-foreground/70"
        />
      </div>
      <div className="flex-1 min-h-0 overflow-auto">
        <div className="py-1">
          {items.map(({ k, i, total }) => {
            const visible = isolated ? k === isolated : !muted.has(k);
            const color = colorFor(i, k);
            const spark = rows.map((r) => Number(r[k] ?? 0));
            return (
              <div
                key={k}
                onClick={() => onToggleMute(k)}
                onDoubleClick={() => onIsolate(k)}
                className={cn(
                  'flex items-center gap-2 px-2.5 py-1.5 cursor-pointer hover:bg-foreground/[0.03] transition-colors select-none',
                  !visible && 'opacity-35',
                )}
                title={k}
              >
                <span className="w-2 h-2 rounded-sm shrink-0" style={{ background: color }} />
                <span className="flex-1 font-mono text-[11px] text-foreground truncate">{k}</span>
                <Sparkline values={spark} color={color} dim={!visible} />
                <span className="font-mono text-[10px] text-muted-foreground tabular-nums w-[42px] text-right shrink-0">
                  {formatY(total)}
                </span>
              </div>
            );
          })}
          {items.length === 0 && (
            <div className="px-2.5 py-4 text-[11px] text-muted-foreground text-center">No series match</div>
          )}
        </div>
      </div>
      <div className="px-2.5 py-1.5 border-t border-border font-mono text-[10px] text-muted-foreground leading-snug">
        click: mute · dbl: isolate
      </div>
    </div>
  );
}

// ────────────────────────────── span ───────────────────────────────

const SPAN_OPTIONS: Array<[string, string]> = [
  ['1m', '1 minute'],
  ['5m', '5 minutes'],
  ['15m', '15 minutes'],
  ['1h', '1 hour'],
  ['6h', '6 hours'],
  ['1d', '1 day'],
];

function SpanChip({ span, onPick }: { span: Span; onPick: (s: string) => void }) {
  const cur = `${span.n}${span.unit}`;
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button
          type="button"
          className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md border border-border text-[10.5px] normal-case tracking-normal font-semibold hover:bg-foreground/5 transition-colors"
        >
          <Clock className="w-[10px] h-[10px] text-primary" />
          <span className="text-foreground">span</span>
          <span className="text-primary font-mono">{cur}</span>
          <ChevronDown className="w-[9px] h-[9px] text-muted-foreground" />
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent className="w-[160px]">
        {SPAN_OPTIONS.map(([k, label]) => (
          <DropdownMenuItem
            key={k}
            onClick={() => onPick(k)}
            className={cn('flex items-center justify-between', k === cur && 'bg-foreground/5')}
          >
            <span className="font-mono text-primary">{k}</span>
            <span className="text-muted-foreground text-[10px]">{label}</span>
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

// ─────────────────────────── pivot table ───────────────────────────

function PivotTable({
  rows,
  seriesKeys,
  visibleKeys,
}: {
  rows: Array<Record<string, unknown>>;
  seriesKeys: string[];
  visibleKeys: string[];
  timeKey: string;
}) {
  // Use visibleKeys order for the columns so muted/isolated series drop out.
  const cols = seriesKeys.filter((k) => visibleKeys.includes(k));
  return (
    <div className="border-t border-border max-h-[60vh] min-h-[240px] overflow-auto bg-muted/20">
      <table className="w-full font-mono text-[11px] border-collapse">
        <thead className="sticky top-0 z-10 bg-card">
          <tr className="border-b border-border text-muted-foreground">
            <th className="py-2 px-3 text-left font-semibold uppercase tracking-[0.12em] text-[10px]">Time</th>
            {cols.map((k) => (
              <th key={k} className="py-2 px-2 text-right font-semibold uppercase tracking-[0.12em] text-[10px]">
                {k}
              </th>
            ))}
            <th className="py-2 px-3 text-right font-semibold uppercase tracking-[0.12em] text-[10px]">Total</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => {
            const total = cols.reduce((s, k) => s + Number(row[k] ?? 0), 0);
            return (
              <tr key={i} className="border-b border-border/50 hover:bg-foreground/[0.03]">
                <td className="py-1 px-3 text-foreground">
                  {formatBucketTime(row.timestamp as number)}
                </td>
                {cols.map((k) => {
                  const v = Number(row[k] ?? 0);
                  return (
                    <td key={k} className="py-1 px-2 text-right text-foreground tabular-nums">
                      {v || ''}
                    </td>
                  );
                })}
                <td className="py-1 px-3 text-right text-foreground font-semibold tabular-nums">{total}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// ─────────────────────────────── root ──────────────────────────────

export function TimechartView({
  results,
  query,
  onSetQuery,
  onDrilldown,
  fieldsCollapsed,
  fieldsCount,
  onExpandFields,
}: TimechartViewProps) {
  const transformed = React.useMemo(() => transformResults(results), [results]);
  const { rows, seriesKeys, seriesTotals, timeKey } = transformed;

  const [muted, setMuted] = React.useState<Set<string>>(new Set());
  const [isolated, setIsolated] = React.useState<string | null>(null);
  const [tableOpen, setTableOpen] = React.useState(true);

  const isVisible = React.useCallback(
    (k: string) => (isolated ? k === isolated : !muted.has(k)),
    [muted, isolated],
  );
  const visibleKeys = React.useMemo(() => seriesKeys.filter(isVisible), [seriesKeys, isVisible]);

  const colorFor = React.useCallback(
    (i: number, k: string) => seriesColor(i, k === 'Other'),
    [seriesKeys.length],
  );

  const toggleMute = (k: string) => {
    if (isolated) {
      setIsolated(null);
      return;
    }
    setMuted((prev) => {
      const next = new Set(prev);
      if (next.has(k)) next.delete(k);
      else next.add(k);
      return next;
    });
  };

  const handleIsolate = (k: string) => {
    setIsolated((cur) => (cur === k ? null : k));
    setMuted(new Set());
  };

  const span = parseSpan(query);
  const { aggLabel, by } = parseTimechartHeader(query);

  const handleSpan = (s: string) => {
    if (!onSetQuery || !query) return;
    onSetQuery(setSpanInQuery(query, s));
  };

  const handleChartClick = (data: unknown) => {
    if (!onDrilldown) return;
    const d = data as { activePayload?: Array<{ payload: Record<string, unknown> }> };
    const payload = d?.activePayload?.[0]?.payload;
    if (payload?.[timeKey]) onDrilldown({ [timeKey]: payload[timeKey] });
  };

  if (!rows.length) {
    return (
      <div className="flex flex-col min-h-0 min-w-0 overflow-hidden">
        <div className="py-2 px-3 border-b border-border flex items-center gap-2 font-mono text-[10.5px] tracking-[0.12em] uppercase text-foreground/70 font-semibold">
          <Activity className="w-[12px] h-[12px] text-primary" />
          <span>Timechart</span>
        </div>
        <div className="p-8 text-center text-muted-foreground text-sm">
          No time buckets returned — check the aggregation field or widen the query scope.
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col min-h-0 overflow-hidden">
      {/* header */}
      <div className="py-2 px-3 border-b border-border flex flex-wrap items-center gap-2 font-mono text-[10.5px] tracking-[0.12em] uppercase text-foreground/70 font-semibold">
        <span className="flex items-center gap-1.5 shrink-0">
          <Activity className="w-[12px] h-[12px] text-primary" />
          <span>Timechart</span>
          <span className="text-muted-foreground/60">·</span>
          <span className="normal-case tracking-normal text-foreground">
            {aggLabel} by {by || '(none)'}
          </span>
        </span>
        {query && onSetQuery && <SpanChip span={span} onPick={handleSpan} />}
        {fieldsCollapsed && onExpandFields && (
          <button
            type="button"
            onClick={onExpandFields}
            className="inline-flex items-center gap-1.5 py-1 px-2 rounded-md border border-primary/25 bg-primary/8 text-primary text-[10px] font-medium cursor-pointer hover:bg-primary/14 transition-colors normal-case tracking-normal shrink-0"
            title="Show field index"
          >
            <span className="relative flex w-[7px] h-[7px] items-center justify-center">
              <span className="absolute inset-0 rounded-full bg-primary/50 animate-ping" />
              <span className="relative w-[4px] h-[4px] rounded-full bg-primary" />
            </span>
            <span className="font-mono uppercase tracking-[0.12em] text-[9.5px]">Fields</span>
            {fieldsCount !== undefined && (
              <span className="text-primary/70 tabular-nums text-[10px]">{fieldsCount}</span>
            )}
            <ChevronRight className="w-[10px] h-[10px]" />
          </button>
        )}
        <span className="flex-1" aria-hidden />
        <button
          type="button"
          onClick={() => setTableOpen((v) => !v)}
          className="flex items-center gap-1 text-muted-foreground hover:text-primary transition-colors"
        >
          <Grid3x3 className="w-[11px] h-[11px]" />
          <span className="normal-case tracking-normal">{tableOpen ? 'Hide table' : 'Show table'}</span>
        </button>
        <button
          type="button"
          title="Export"
          className="text-muted-foreground hover:text-primary p-1 cursor-pointer"
        >
          <Download className="w-[12px] h-[12px]" />
        </button>
      </div>

      {/* body: chart + legend */}
      <div className="flex-1 min-h-0 grid grid-cols-[1fr_220px] overflow-hidden">
        {/* chart */}
        <div className="relative min-h-0 overflow-hidden p-3 min-h-[320px]">
          <ResponsiveContainer width="100%" height="100%" minHeight={300}>
            <AreaChart
              data={rows}
              margin={{ top: 8, right: 8, left: 0, bottom: 4 }}
              onClick={handleChartClick}
            >
              <CartesianGrid
                strokeDasharray="2 3"
                stroke="var(--border)"
                strokeOpacity={0.5}
                vertical={false}
              />
              <XAxis
                dataKey="timestamp"
                type="number"
                scale="time"
                domain={['dataMin', 'dataMax']}
                tickFormatter={(v) => formatBucketTime(v as number)}
                tick={{ fontSize: 10, fill: 'var(--muted-foreground)' }}
                axisLine={{ stroke: 'var(--border)' }}
                tickLine={false}
              />
              <YAxis
                tickFormatter={(v) => formatY(v as number)}
                tick={{ fontSize: 10, fill: 'var(--muted-foreground)' }}
                axisLine={false}
                tickLine={false}
                width={44}
              />
              <Tooltip
                content={<ChartTooltip />}
                cursor={{ stroke: 'var(--foreground)', strokeOpacity: 0.3, strokeWidth: 1 }}
              />
              {seriesKeys.map((k, i) => {
                const visible = isVisible(k);
                const color = colorFor(i, k);
                return (
                  <Area
                    key={k}
                    type="monotone"
                    dataKey={k}
                    name={k}
                    hide={!visible}
                    stroke={color}
                    strokeOpacity={0.9}
                    strokeWidth={1.5}
                    fill={color}
                    fillOpacity={0.22}
                    isAnimationActive={false}
                  />
                );
              })}
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* legend */}
        <Legend
          seriesKeys={seriesKeys}
          seriesTotals={seriesTotals}
          rows={rows}
          muted={muted}
          isolated={isolated}
          onToggleMute={toggleMute}
          onIsolate={handleIsolate}
          colorFor={colorFor}
        />
      </div>

      {/* pivot table */}
      {tableOpen && (
        <PivotTable rows={rows} seriesKeys={seriesKeys} visibleKeys={visibleKeys} timeKey={timeKey} />
      )}
    </div>
  );
}
