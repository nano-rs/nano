// SPDX-License-Identifier: AGPL-3.0-or-later

import React from 'react';
import { BarChart3, ChevronRight, Download, Grid3x3, TrendingDown } from 'lucide-react';
import { cn } from '@/lib/utils';

interface SearchResult {
  id: string;
  timestamp: Date;
  source: string;
  fields: Record<string, unknown>;
}

interface RankedBarChartProps {
  results: SearchResult[];
  query?: string;
  onDrilldown?: (filters: Record<string, unknown>) => void;
  fieldsCollapsed?: boolean;
  fieldsCount?: number;
  onExpandFields?: () => void;
}

// ───────────────────────────── helpers ─────────────────────────────

function formatNum(v: number): string {
  if (v >= 1_000_000) return (v / 1_000_000).toFixed(1) + 'M';
  if (v >= 10_000) return (v / 1_000).toFixed(1) + 'k';
  if (v >= 1_000) return v.toLocaleString();
  return String(Math.round(v));
}

function niceStep(v: number): number {
  if (!isFinite(v) || v <= 0) return 1;
  const mag = Math.pow(10, Math.floor(Math.log10(v)));
  const f = v / mag;
  let n: number;
  if (f < 1.5) n = 1;
  else if (f < 3) n = 2;
  else if (f < 7) n = 5;
  else n = 10;
  return n * mag;
}

/** Brightest at rank 0, darker toward last. Keeps brand hue. */
function topColor(rank: number, n: number): string {
  const denom = Math.max(1, n - 1);
  const t = rank / denom;
  const L = 72 - t * 22;
  const C = 0.14 - t * 0.05;
  const H = 202 - t * 4;
  return `oklch(${L.toFixed(1)}% ${C.toFixed(3)} ${H.toFixed(0)})`;
}
/** Warm red signal at rank 0 (rarest), fading toward muted. */
function rareColor(rank: number, n: number): string {
  const denom = Math.max(1, n - 1);
  const t = rank / denom;
  const L = 64 + t * 10;
  const C = 0.18 - t * 0.12;
  const H = 25 + t * 10;
  return `oklch(${L.toFixed(1)}% ${C.toFixed(3)} ${H.toFixed(0)})`;
}

const RARE_ACCENT = 'oklch(60% 0.18 25)';

type Kind = 'top' | 'rare';

function detectKind(query: string | undefined): Kind {
  return /\|\s*rare\b/i.test(query ?? '') ? 'rare' : 'top';
}

function parseLimit(query: string | undefined): number | null {
  const m = query?.match(/\|\s*(?:top|rare)\s+(\d+)\b/i);
  return m ? parseInt(m[1], 10) : null;
}

// ─────────────────────────── data transform ─────────────────────────

interface Row {
  rank: number;
  parts: string[];
  composite: string;
  count: number;
  pct: number;
}

interface Transformed {
  rows: Row[];
  labelKeys: string[];
  max: number;
}

function transform(results: SearchResult[]): Transformed {
  if (!results.length) return { rows: [], labelKeys: [], max: 0 };

  const sample = results[0]?.fields ?? {};
  const fieldNames = Object.keys(sample);

  // count column: `count` / `total` / `count_*` / else first numeric
  let countKey: string | null = null;
  for (const k of fieldNames) {
    const lower = k.toLowerCase();
    if ((lower === 'count' || lower === 'total' || lower.startsWith('count_'))
        && typeof sample[k] === 'number') {
      countKey = k;
      break;
    }
  }
  if (!countKey) {
    for (const k of fieldNames) {
      if (typeof sample[k] === 'number') { countKey = k; break; }
    }
  }

  // pre-supplied percent column if any; we recompute over the top-N anyway
  const percentKey = fieldNames.find((k) =>
    k.toLowerCase().includes('percent') && typeof sample[k] === 'number',
  );

  const labelKeys = fieldNames.filter((k) => k !== countKey && k !== percentKey);

  const raw = results.map((r) => {
    const f = r.fields ?? {};
    const parts = labelKeys.map((k) => String(f[k] ?? ''));
    const count = countKey ? Number(f[countKey] ?? 0) : 0;
    return { parts, count };
  });

  const total = raw.reduce((s, x) => s + x.count, 0);
  const max = raw.reduce((m, x) => Math.max(m, x.count), 0);

  const rows: Row[] = raw.map((x, i) => ({
    rank: i,
    parts: x.parts,
    composite: x.parts.join(' › '),
    count: x.count,
    pct: total > 0 ? (x.count / total) * 100 : 0,
  }));

  return { rows, labelKeys, max };
}

// ───────────────────────────── bars ─────────────────────────────────

const GRID_COLS = '28px minmax(120px, 280px) 1fr';

function BarChart({
  rows,
  kind,
  hoverRank,
  setHoverRank,
  colorFor,
}: {
  rows: Row[];
  kind: Kind;
  hoverRank: number | null;
  setHoverRank: (r: number | null) => void;
  colorFor: (rank: number) => string;
}) {
  const max = rows.reduce((m, r) => Math.max(m, r.count), 0);
  const tickStep = niceStep(max / 4);
  const ticks: number[] = [];
  for (let v = 0; v <= max; v += tickStep) ticks.push(v);
  if (ticks.length && ticks[ticks.length - 1] < max) ticks.push(max);

  return (
    <div className="min-h-0 overflow-auto">
      <div className="px-4 py-3">
        <div className="flex flex-col">
          {rows.map((r) => {
            const isHover = hoverRank === r.rank;
            const clr = colorFor(r.rank);
            const pctWidth = max > 0 ? Math.max(0.8, (r.count / max) * 100) : 0;
            return (
              <div
                key={r.rank}
                onMouseEnter={() => setHoverRank(r.rank)}
                onMouseLeave={() => setHoverRank(null)}
                className={cn(
                  'grid items-center gap-4 h-[24px] rounded-sm px-1 transition-colors',
                  isHover ? 'bg-primary/8' : hoverRank !== null && 'opacity-60',
                )}
                style={{ gridTemplateColumns: GRID_COLS }}
              >
                <span className="font-mono text-[9.5px] text-muted-foreground/70 tabular-nums text-right">
                  {String(r.rank + 1).padStart(2, '0')}
                </span>
                <span
                  className="font-mono text-[11.5px] text-foreground text-right truncate"
                  title={r.composite}
                >
                  {r.composite}
                </span>
                <div className="relative h-full flex items-center">
                  <div
                    className="h-[11px] rounded-[3px] transition-[width]"
                    style={{ width: `${pctWidth}%`, background: clr, minWidth: 2 }}
                  />
                  <span
                    className="font-mono text-[11px] tabular-nums font-semibold pl-2 whitespace-nowrap"
                    style={{ color: isHover ? 'var(--primary)' : 'var(--foreground)' }}
                  >
                    {formatNum(r.count)}
                  </span>
                  <span className="font-mono text-[9.5px] text-muted-foreground/70 tabular-nums pl-1.5 whitespace-nowrap">
                    {r.pct < 0.1 ? '<0.1%' : r.pct.toFixed(1) + '%'}
                  </span>
                </div>
              </div>
            );
          })}
        </div>

        {/* X axis */}
        <div
          className="grid items-center gap-4 mt-2 pt-1.5 border-t border-border/60"
          style={{ gridTemplateColumns: GRID_COLS }}
        >
          <span />
          <span className="font-mono text-[9px] text-muted-foreground/70 text-right uppercase tracking-[0.14em]">
            {kind === 'rare' ? '← rarer' : 'count →'}
          </span>
          <div className="relative h-[14px]">
            {ticks.map((t, i) => (
              <span
                key={i}
                className="absolute -translate-x-1/2 font-mono text-[9px] text-muted-foreground/70 tabular-nums top-0"
                style={{ left: `${max > 0 ? (t / max) * 100 : 0}%`, display: t === 0 ? 'none' : undefined }}
              >
                {formatNum(t)}
              </span>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// ───────────────────────────── table ─────────────────────────────────

function RankedTable({
  rows,
  labelKeys,
  hoverRank,
  setHoverRank,
  colorFor,
  onDrilldown,
}: {
  rows: Row[];
  labelKeys: string[];
  hoverRank: number | null;
  setHoverRank: (r: number | null) => void;
  colorFor: (rank: number) => string;
  onDrilldown?: (filters: Record<string, unknown>) => void;
}) {
  const max = rows.reduce((m, r) => Math.max(m, r.count), 0);
  return (
    <div className="border-t border-border max-h-[60vh] min-h-[240px] overflow-auto bg-muted/20">
      <table className="w-full font-mono text-[11px] border-collapse">
        <thead className="sticky top-0 z-10 bg-card">
          <tr className="border-b border-border text-muted-foreground">
            <th className="py-2 px-3 text-right font-semibold uppercase tracking-[0.12em] text-[10px] w-[44px]">#</th>
            {labelKeys.map((f) => (
              <th key={f} className="py-2 px-3 text-left font-semibold uppercase tracking-[0.12em] text-[10px]">
                {f}
              </th>
            ))}
            <th className="py-2 px-3 text-right font-semibold uppercase tracking-[0.12em] text-[10px] w-[80px]">Count</th>
            <th className="py-2 px-3 text-right font-semibold uppercase tracking-[0.12em] text-[10px] w-[64px]">%</th>
            <th className="py-2 px-3 text-left font-semibold uppercase tracking-[0.12em] text-[10px] w-[28%]">Share</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => {
            const isHover = hoverRank === r.rank;
            const clr = colorFor(r.rank);
            return (
              <tr
                key={r.rank}
                onMouseEnter={() => setHoverRank(r.rank)}
                onMouseLeave={() => setHoverRank(null)}
                onClick={() => {
                  if (onDrilldown && labelKeys.length) {
                    const filters: Record<string, unknown> = {};
                    labelKeys.forEach((k, i) => { filters[k] = r.parts[i]; });
                    onDrilldown(filters);
                  }
                }}
                className={cn(
                  'border-b border-border/50 transition-colors',
                  onDrilldown ? 'cursor-pointer' : 'cursor-default',
                  isHover ? 'bg-primary/8' : 'hover:bg-foreground/[0.03]',
                )}
              >
                <td className="py-1.5 px-3 text-right text-muted-foreground tabular-nums">
                  {String(r.rank + 1).padStart(2, '0')}
                </td>
                {r.parts.map((p, i) => (
                  <td key={i} className="py-1.5 px-3 text-foreground truncate max-w-[220px]">
                    {i === 0 && (
                      <span
                        className="inline-block w-1.5 h-1.5 rounded-full mr-2 align-middle"
                        style={{ background: clr }}
                      />
                    )}
                    {p}
                  </td>
                ))}
                <td className="py-1.5 px-3 text-right text-foreground tabular-nums font-semibold">
                  {formatNum(r.count)}
                </td>
                <td className="py-1.5 px-3 text-right text-foreground/85 tabular-nums">
                  {r.pct < 0.1 ? '<0.1%' : r.pct.toFixed(1) + '%'}
                </td>
                <td className="py-1.5 px-3">
                  <div className="h-1.5 rounded-full bg-foreground/10 overflow-hidden">
                    <div
                      className="h-full rounded-full"
                      style={{ width: `${max > 0 ? (r.count / max) * 100 : 0}%`, background: clr }}
                    />
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// ───────────────────────────── root ─────────────────────────────────

export function RankedBarChart({
  results,
  query,
  onDrilldown,
  fieldsCollapsed,
  fieldsCount,
  onExpandFields,
}: RankedBarChartProps) {
  const { rows, labelKeys } = React.useMemo(() => transform(results), [results]);

  const kind = detectKind(query);
  const isRare = kind === 'rare';
  const limit = parseLimit(query);

  const [hoverRank, setHoverRank] = React.useState<number | null>(null);
  // Default open to match Timechart convention; user can collapse.
  const [tableOpen, setTableOpen] = React.useState(true);

  const colorFor = React.useCallback(
    (rank: number) => (isRare ? rareColor(rank, rows.length) : topColor(rank, rows.length)),
    [isRare, rows.length],
  );

  if (!rows.length) {
    return (
      <div className="flex flex-col min-h-0 min-w-0 overflow-hidden">
        <div className="py-2 px-3 border-b border-border flex items-center gap-2 font-mono text-[10.5px] tracking-[0.12em] uppercase text-foreground/70 font-semibold">
          {isRare ? (
            <TrendingDown className="w-[12px] h-[12px]" style={{ color: RARE_ACCENT }} />
          ) : (
            <BarChart3 className="w-[12px] h-[12px] text-primary" />
          )}
          <span>{isRare ? 'Rare' : 'Top'}</span>
        </div>
        <div className="p-8 text-center text-muted-foreground text-sm">
          No values returned — try widening the time range or checking the field name.
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col min-h-0 overflow-hidden">
      {/* header */}
      <div className="py-2 px-3 border-b border-border flex flex-wrap items-center gap-2 font-mono text-[10.5px] tracking-[0.12em] uppercase text-foreground/70 font-semibold">
        <span className="flex items-center gap-1.5 shrink-0">
          {isRare ? (
            <TrendingDown className="w-[12px] h-[12px]" style={{ color: RARE_ACCENT }} />
          ) : (
            <BarChart3 className="w-[12px] h-[12px] text-primary" />
          )}
          <span>{isRare ? 'Rare' : 'Top'}</span>
          <span className="text-muted-foreground/60">·</span>
          <span className="normal-case tracking-normal text-foreground">
            {labelKeys.join(', ') || '(field)'}
          </span>
        </span>
        {isRare && (
          <span
            className="inline-flex items-center px-1.5 py-[1px] rounded-sm text-[9px] font-bold tracking-[0.14em]"
            style={{
              background: 'oklch(60% 0.18 25 / 0.14)',
              color: RARE_ACCENT,
              border: '1px solid oklch(60% 0.18 25 / 0.35)',
            }}
          >
            LOW‑FREQ SIGNAL
          </span>
        )}
        {limit !== null && (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md border border-border text-[10px] normal-case tracking-normal font-semibold text-foreground">
            <span className="text-muted-foreground">limit</span>
            <span className="text-primary font-mono">{limit}</span>
          </span>
        )}
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
        <span className="text-muted-foreground font-mono normal-case tracking-normal">
          {rows.length} values
        </span>
        <button
          type="button"
          onClick={() => setTableOpen((v) => !v)}
          className="flex items-center gap-1 text-muted-foreground hover:text-primary transition-colors normal-case tracking-normal"
        >
          <Grid3x3 className="w-[11px] h-[11px]" />
          <span>{tableOpen ? 'Hide table' : 'Show table'}</span>
        </button>
        <button
          type="button"
          title="Export"
          className="text-muted-foreground hover:text-primary p-1 cursor-pointer"
        >
          <Download className="w-[12px] h-[12px]" />
        </button>
      </div>

      {/* body: bars (+ optional table) */}
      <div className="flex-1 min-h-0 grid grid-rows-[minmax(0,1fr)_auto] overflow-hidden">
        <BarChart
          rows={rows}
          kind={kind}
          hoverRank={hoverRank}
          setHoverRank={setHoverRank}
          colorFor={colorFor}
        />
        {tableOpen && (
          <RankedTable
            rows={rows}
            labelKeys={labelKeys}
            hoverRank={hoverRank}
            setHoverRank={setHoverRank}
            colorFor={colorFor}
            onDrilldown={onDrilldown}
          />
        )}
      </div>
    </div>
  );
}
