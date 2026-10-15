// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-3194: Log Sources "Ingestion activity" stacked area chart.
 *
 * The chart used to be a fixed 1360-wide viewBox stretched with
 * `preserveAspectRatio="none"`, which scaled the axis `<text>` non-uniformly
 * (squashed / smeared labels). It now measures its container with a
 * ResizeObserver and draws at real pixels, so text is never scaled.
 *
 * Also adds a hover crosshair + tooltip snapped to the nearest bucket, and a
 * legend whose items toggle series on/off (persisted per-browser).
 */
import { useCallback, useLayoutEffect, useMemo, useRef, useState } from 'react';
import type { KeyboardEvent, MouseEvent } from 'react';
import { Rss } from 'lucide-react';

import { formatUTCCompact, parseUTCTimestamp } from '@/lib/date-utils';
import { INTERNAL_SERIES } from '@/lib/log-source-lanes';
import { cn } from '@/lib/utils';

export type IngestionPoint = { source_type: string; timestamp: string; count: number };

export const INGEST_CHART_HIDDEN_STORAGE_KEY = 'nano.logsources.ingestChart.hidden';

const CHART_PALETTE = [
  'oklch(72% 0.15 200)', // cyan
  'oklch(70% 0.17 250)', // blue
  'oklch(72% 0.15 160)', // teal
  'oklch(74% 0.14 110)', // lime
  'oklch(76% 0.14 80)', // gold
  'oklch(72% 0.16 40)', // orange
  'oklch(70% 0.16 10)', // coral
  'oklch(68% 0.17 320)', // magenta
  'oklch(68% 0.16 280)', // violet
];

function fmtRate(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return Math.round(n).toString();
}

const H = 150;
const PAD_L = 44;
const PAD_R = 12;
const PAD_T = 6;
const PAD_B = 24;
const TOOLTIP_W = 196;
const FALLBACK_W = 1360;

function readHidden(): Set<string> {
  try {
    const raw = window.localStorage.getItem(INGEST_CHART_HIDDEN_STORAGE_KEY);
    if (!raw) return new Set();
    const parsed: unknown = JSON.parse(raw);
    return Array.isArray(parsed)
      ? new Set(parsed.filter((v): v is string => typeof v === 'string'))
      : new Set();
  } catch {
    return new Set();
  }
}

function writeHidden(hidden: Set<string>) {
  try {
    window.localStorage.setItem(INGEST_CHART_HIDDEN_STORAGE_KEY, JSON.stringify([...hidden]));
  } catch {
    // Storage unavailable (private mode, blocked site data) — keep in-memory state only.
  }
}

function useMeasuredWidth(fallback: number): [React.RefObject<HTMLDivElement | null>, number] {
  const ref = useRef<HTMLDivElement>(null);
  const [w, setW] = useState(fallback);
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const initial = el.getBoundingClientRect().width;
    if (initial > 0) setW(Math.round(initial));
    if (typeof ResizeObserver === 'undefined') return;
    const ro = new ResizeObserver((entries) => {
      const cw = entries[0]?.contentRect.width;
      if (cw && cw > 0) setW(Math.round(cw));
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  return [ref, w];
}

export function IngestionActivityChart({ history }: { history: IngestionPoint[] }) {
  const [hidden, setHidden] = useState<Set<string>>(readHidden);
  const [hoverIdx, setHoverIdx] = useState<number | null>(null);
  const [wrapRef, W] = useMeasuredWidth(FALLBACK_W);

  // Pivot ingestion-history points into per-source series over sorted buckets.
  // Colors are assigned from the full source list so they stay stable when a
  // series is hidden.
  const { timestamps, series, bucketSeconds } = useMemo(() => {
    if (!history.length) {
      return { timestamps: [] as string[], series: [] as SeriesDef[], bucketSeconds: 0 };
    }
    const types = Array.from(new Set(history.map((p) => p.source_type)));
    const byTime = new Map<string, Map<string, number>>();
    for (const p of history) {
      let row = byTime.get(p.timestamp);
      if (!row) {
        row = new Map();
        byTime.set(p.timestamp, row);
      }
      row.set(p.source_type, (row.get(p.source_type) ?? 0) + p.count);
    }
    const ts = Array.from(byTime.keys()).sort();
    const defs: SeriesDef[] = types.map((t, i) => ({
      id: t,
      // NAN-3248: internal series (e.g. detection `findings`) are labelled as such.
      label: INTERNAL_SERIES[t]?.label ?? t,
      title: INTERNAL_SERIES[t]?.title,
      color: CHART_PALETTE[i % CHART_PALETTE.length],
      points: ts.map((x) => byTime.get(x)?.get(t) ?? 0),
    }));
    let bucket = 0;
    if (ts.length >= 2) {
      bucket = (parseUTCTimestamp(ts[1]).getTime() - parseUTCTimestamp(ts[0]).getTime()) / 1000;
    }
    return { timestamps: ts, series: defs, bucketSeconds: bucket };
  }, [history]);

  // Hidden ids that no longer exist in the data don't count; if every present
  // series is hidden (stale storage), show everything rather than an empty chart.
  const effectiveHidden = useMemo(() => {
    const present = series.filter((s) => hidden.has(s.id));
    return present.length >= series.length ? new Set<string>() : hidden;
  }, [series, hidden]);

  const { stacked, maxY } = useMemo(() => {
    const N = timestamps.length;
    const running = new Array(N).fill(0) as number[];
    const out = series
      .filter((s) => !effectiveHidden.has(s.id))
      .map((s) => {
        const lower = [...running];
        for (let i = 0; i < N; i++) running[i] += s.points[i];
        return { ...s, lower, upper: [...running] };
      });
    return { stacked: out, maxY: Math.max(1, ...running) };
  }, [timestamps, series, effectiveHidden]);

  const toggle = useCallback(
    (id: string) => {
      setHidden((prev) => {
        const next = new Set(prev);
        if (next.has(id)) {
          next.delete(id);
        } else {
          const visible = series.filter((s) => !effectiveHidden.has(s.id));
          if (visible.length <= 1) return prev; // never hide the last visible series
          next.add(id);
        }
        writeHidden(next);
        return next;
      });
    },
    [series, effectiveHidden],
  );

  const N = timestamps.length;
  const innerW = Math.max(1, W - PAD_L - PAD_R);
  const innerH = H - PAD_T - PAD_B;
  const xAt = (i: number) => (N <= 1 ? PAD_L : PAD_L + (i / (N - 1)) * innerW);
  const yAt = (v: number) => PAD_T + innerH - (v / Math.max(maxY, 1)) * innerH;

  const pathFor = (layer: { lower: number[]; upper: number[] }) => {
    const top = layer.upper
      .map((v, i) => `${i === 0 ? 'M' : 'L'}${xAt(i).toFixed(1)},${yAt(v).toFixed(1)}`)
      .join(' ');
    const bot = layer.lower
      .map((_, i) => `L${xAt(N - 1 - i).toFixed(1)},${yAt(layer.lower[N - 1 - i]).toFixed(1)}`)
      .join(' ');
    return `${top} ${bot} Z`;
  };

  // Normalize per-bucket counts to evt/min when the bucket size is known;
  // otherwise show raw per-bucket counts rather than mislead.
  const perMin = (count: number) => (bucketSeconds > 0 ? (count * 60) / bucketSeconds : count);
  const rateUnit = bucketSeconds > 0 ? 'evt/min' : 'evt';
  const peakPerMin = bucketSeconds > 0 ? (maxY * 60) / bucketSeconds : 0;

  const onMouseMove = (e: MouseEvent<HTMLDivElement>) => {
    if (N === 0) return;
    const rect = e.currentTarget.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const idx = N <= 1 ? 0 : Math.round(((x - PAD_L) / innerW) * (N - 1));
    setHoverIdx(Math.min(N - 1, Math.max(0, idx)));
  };

  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    if (N === 0) return;
    if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') {
      e.preventDefault();
      const d = e.key === 'ArrowLeft' ? -1 : 1;
      setHoverIdx((cur) => Math.min(N - 1, Math.max(0, (cur ?? (d > 0 ? -1 : N)) + d)));
    } else if (e.key === 'Escape') {
      setHoverIdx(null);
    }
  };

  const hoverX = hoverIdx != null ? xAt(hoverIdx) : 0;
  // Flip the tooltip to the left of the crosshair near the right edge, and clamp
  // it inside the chart either way.
  const tooltipLeft =
    hoverIdx == null
      ? 0
      : hoverX + 10 + TOOLTIP_W > W
        ? Math.max(0, hoverX - 10 - TOOLTIP_W)
        : hoverX + 10;
  const hoverRows =
    hoverIdx == null
      ? []
      : [...stacked].reverse().map((s) => ({ id: s.id, color: s.color, v: s.points[hoverIdx] }));
  const hoverTotal = hoverRows.reduce((a, r) => a + r.v, 0);

  const yTicks = [0, 0.5, 1];
  const xTicks = [0, 0.25, 0.5, 0.75, 1];

  return (
    <div className="rounded-lg border border-border bg-card overflow-hidden">
      <div className="flex items-center gap-2 px-4 py-2.5 border-b border-border">
        <Rss className="w-3.5 h-3.5 text-muted-foreground" />
        <div className="text-[11.5px] font-medium text-foreground whitespace-nowrap">Ingestion activity</div>
        <span className="text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground whitespace-nowrap">
          24h · stacked by source type
        </span>
        <div className="flex-1" />
        {peakPerMin > 0 && (
          <div
            className="text-[10.5px] font-mono text-muted-foreground tabular-nums whitespace-nowrap"
            data-testid="ingest-chart-peak"
          >
            Peak ≈ <span className="text-foreground">{fmtRate(peakPerMin)}</span>{' '}
            <span className="text-muted-foreground/70">evt/min</span>
          </div>
        )}
      </div>
      <div className="p-2">
        {series.length === 0 ? (
          <div className="h-[150px] flex items-center justify-center text-[11px] text-muted-foreground">
            No ingestion activity in the last 24 hours.
          </div>
        ) : (
          <div
            ref={wrapRef}
            className="relative w-full h-[150px] outline-none focus-visible:ring-1 focus-visible:ring-ring rounded-sm"
            data-testid="ingest-chart-plot"
            tabIndex={0}
            role="group"
            aria-label="Ingestion activity chart. Use left and right arrow keys to inspect buckets."
            onMouseMove={onMouseMove}
            onMouseLeave={() => setHoverIdx(null)}
            onKeyDown={onKeyDown}
            onBlur={() => setHoverIdx(null)}
          >
            <svg width={W} height={H} viewBox={`0 0 ${W} ${H}`} className="block" aria-hidden="true">
              {[0, 0.25, 0.5, 0.75, 1].map((f, i) => {
                const y = PAD_T + innerH - f * innerH;
                return (
                  <line
                    key={i}
                    x1={PAD_L}
                    x2={W - PAD_R}
                    y1={y}
                    y2={y}
                    stroke="var(--border)"
                    strokeWidth="1"
                    strokeDasharray={i === 0 ? '' : '2,3'}
                  />
                );
              })}
              {yTicks.map((f, i) => {
                const y = PAD_T + innerH - f * innerH;
                const v = peakPerMin > 0 ? f * peakPerMin : f * maxY;
                return (
                  <text
                    key={`y${i}`}
                    data-testid="ingest-chart-axis-label"
                    x={PAD_L - 6}
                    y={y + 3}
                    textAnchor="end"
                    fontFamily="var(--font-mono, ui-monospace)"
                    fontSize="10.5"
                    fill="var(--muted-foreground)"
                  >
                    {fmtRate(v)}
                  </text>
                );
              })}
              {xTicks.map((f, i) => {
                const x = PAD_L + f * innerW;
                const h = Math.round(24 - f * 24);
                return (
                  <text
                    key={`x${i}`}
                    data-testid="ingest-chart-axis-label"
                    x={x}
                    y={H - 8}
                    textAnchor={f === 1 ? 'end' : f === 0 ? 'start' : 'middle'}
                    fontFamily="var(--font-mono, ui-monospace)"
                    fontSize="10.5"
                    fill="var(--muted-foreground)"
                  >
                    {h === 0 ? 'now' : `-${h}h`}
                  </text>
                );
              })}
              {stacked.map((layer) => (
                <path
                  key={layer.id}
                  data-testid={`ingest-chart-series-${layer.id}`}
                  d={pathFor(layer)}
                  fill={layer.color}
                  fillOpacity="0.72"
                  stroke={layer.color}
                  strokeWidth="0.75"
                  strokeOpacity="0.9"
                />
              ))}
              {hoverIdx != null && (
                <line
                  x1={hoverX}
                  x2={hoverX}
                  y1={PAD_T}
                  y2={PAD_T + innerH}
                  stroke="var(--foreground)"
                  strokeOpacity="0.5"
                  strokeWidth="1"
                  pointerEvents="none"
                />
              )}
            </svg>
            {hoverIdx != null && (
              <div
                role="tooltip"
                data-testid="ingest-chart-tooltip"
                className="pointer-events-none absolute top-1 z-10 rounded-md border border-border bg-popover text-popover-foreground shadow-md px-2.5 py-1.5"
                style={{ left: tooltipLeft, width: TOOLTIP_W }}
              >
                <div className="font-mono text-[10.5px] text-muted-foreground tabular-nums pb-1 mb-1 border-b border-border">
                  {formatUTCCompact(parseUTCTimestamp(timestamps[hoverIdx]))}
                </div>
                {hoverRows.map((r) => (
                  <div key={r.id} className="flex items-center gap-1.5 h-[18px]">
                    <span className="w-2 h-2 rounded-sm shrink-0" style={{ background: r.color }} />
                    <span className="text-[11px] text-foreground/80 truncate flex-1">{r.id}</span>
                    <span className="font-mono text-[10.5px] tabular-nums text-foreground">
                      {fmtRate(perMin(r.v))}
                    </span>
                  </div>
                ))}
                <div className="flex items-center gap-1.5 h-[18px] mt-1 pt-1 border-t border-border">
                  <span className="text-[11px] text-muted-foreground flex-1">Total</span>
                  <span className="font-mono text-[10.5px] tabular-nums text-foreground">
                    {fmtRate(perMin(hoverTotal))}
                  </span>
                  <span className="font-mono text-[10px] text-muted-foreground/70">{rateUnit}</span>
                </div>
              </div>
            )}
          </div>
        )}
        {series.length > 0 && (
          <div className="flex items-center gap-1 flex-wrap px-1 pt-1.5 pb-1">
            {series.map((s) => {
              const isHidden = effectiveHidden.has(s.id);
              return (
                <button
                  key={s.id}
                  type="button"
                  aria-pressed={!isHidden}
                  title={`${isHidden ? 'Show' : 'Hide'} ${s.label}${s.title ? ` · ${s.title}` : ''}`}
                  data-testid={`ingest-chart-legend-${s.id}`}
                  onClick={() => toggle(s.id)}
                  className={cn(
                    'flex items-center gap-1.5 h-6 px-1.5 rounded-sm cursor-pointer hover:bg-muted/60',
                    isHidden && 'opacity-40',
                  )}
                >
                  <span
                    className="w-2 h-2 rounded-sm"
                    style={isHidden ? { border: `1px solid ${s.color}` } : { background: s.color }}
                  />
                  <span className={cn('text-[10.5px] text-foreground/80', isHidden && 'line-through')}>
                    {s.label}
                  </span>
                </button>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

type SeriesDef = { id: string; label: string; title?: string; color: string; points: number[] };
