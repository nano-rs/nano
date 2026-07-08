// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Observability chart primitives (NAN-1536)
 *
 * Ported from the design handoff's obs-charts.jsx / obs-charts2.jsx as
 * presentational TSX (data in, SVG out — no fetching, no app state). The
 * hand-rolled SVG is kept rather than Recharts: it's tiny, exact to the design,
 * and avoids a lazy-chunk per surface. Colors flow through CSS custom props so
 * they track the active theme (see index.css obs aliases).
 *
 *   Sparkline       — line + optional area fill, for the Services list
 *   REDChart        — multi-series time chart w/ grid, crosshair, deploy markers
 *   LatencyScatter  — x=time, y=duration (sqrt scale), red dots = errored traces
 *   BudgetBar       — SLO error-budget consumed bar
 */

import { useLayoutEffect, useMemo, useRef, useState } from 'react';
import { GitCommit } from 'lucide-react';
import { parseUTCTimestamp } from '@/lib/date-utils';

// Track the rendered pixel width of a wrapper so SVG charts can size their
// viewBox to match it 1:1. Without this, a fixed viewBox width stretched to
// `w-full` distorts everything non-uniformly (oval dots, smeared labels) once
// the container is wider than the old fixed value.
function useMeasuredWidth(fallback: number): [React.RefObject<HTMLDivElement | null>, number] {
  const ref = useRef<HTMLDivElement>(null);
  const [w, setW] = useState(fallback);
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const ro = new ResizeObserver((entries) => {
      const cw = entries[0]?.contentRect.width;
      if (cw && cw > 0) setW(Math.round(cw));
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  return [ref, w];
}

// ---------------------------------------------------------------------------
// Sparkline
// ---------------------------------------------------------------------------

export interface SparklineProps {
  data: number[];
  color?: string;
  fill?: boolean;
  w?: number;
  h?: number;
  strokeW?: number;
}

export function Sparkline({
  data,
  color = 'var(--color-brand)',
  fill = false,
  w = 80,
  h = 22,
  strokeW = 1.25,
}: SparklineProps) {
  const gid = useMemo(() => 'sg' + Math.random().toString(36).slice(2, 8), []);
  if (data.length === 0) return <svg width={w} height={h} />;
  const max = Math.max(1, ...data);
  const min = Math.min(...data);
  const span = Math.max(1e-6, max - min);
  const X = (i: number) => (data.length === 1 ? w / 2 : (i / (data.length - 1)) * w);
  const Y = (v: number) => h - 2 - ((v - min) / span) * (h - 4);
  const pts = data.map((v, i) => `${X(i).toFixed(1)},${Y(v).toFixed(1)}`).join(' L ');
  return (
    <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} className="block overflow-visible">
      {fill && (
        <>
          <defs>
            <linearGradient id={gid} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={color} stopOpacity="0.28" />
              <stop offset="100%" stopColor={color} stopOpacity="0" />
            </linearGradient>
          </defs>
          <path d={`M 0,${h} L ${pts} L ${w},${h} Z`} fill={`url(#${gid})`} />
        </>
      )}
      <path
        d={`M ${pts}`}
        fill="none"
        stroke={color}
        strokeWidth={strokeW}
        strokeLinejoin="round"
        strokeLinecap="round"
      />
    </svg>
  );
}

// ---------------------------------------------------------------------------
// REDChart — multi-series time-series
// ---------------------------------------------------------------------------

export interface RedSeries {
  /**
   * Y values, one per bucket (must align with `buckets` by index). `null` marks
   * a gap (no data for that bucket) — the line breaks and the area drops out
   * there rather than interpolating across the hole.
   */
  points: Array<number | null>;
  /** Stroke color (CSS color or var). */
  color: string;
  /** Legend / tooltip label. */
  label: string;
  /** Dashed stroke (e.g. for a percentile line). */
  dashed?: boolean;
  /** Fill the area under the line. */
  fill?: boolean;
}

export interface RedMarker {
  /** Bucket index the marker sits on. */
  idx: number;
  /** Short label (e.g. a deploy version). */
  label: string;
}

export interface REDChartProps {
  series: RedSeries[];
  /** Bucket timestamps (ms epoch or anything `new Date()` parses), per point. */
  buckets: Array<number | string>;
  yFmt?: (v: number) => string;
  height?: number;
  unit?: string;
  markers?: RedMarker[];
}

const niceStep = (v: number): number => {
  if (v <= 0) return 1;
  const mag = Math.pow(10, Math.floor(Math.log10(v)));
  const f = v / mag;
  return (f < 1.5 ? 1 : f < 3 ? 2 : f < 7 ? 5 : 10) * mag;
};

const hhmm = (ts: number | string): string => {
  // Numbers are epoch-ms (timezone-agnostic); strings are backend timestamps
  // WITHOUT a zone suffix, which `new Date()` would misread as local time.
  // Route the string case through parseUTCTimestamp so labels stay in UTC (O12).
  const d = typeof ts === 'number' ? new Date(ts) : parseUTCTimestamp(ts);
  if (Number.isNaN(d.getTime())) return '';
  const p = (x: number) => String(x).padStart(2, '0');
  return `${p(d.getUTCHours())}:${p(d.getUTCMinutes())}`;
};

export function REDChart({
  series,
  buckets,
  yFmt = (v) => String(Math.round(v)),
  height = 150,
  unit = '',
  markers = [],
}: REDChartProps) {
  const ref = useRef<SVGSVGElement>(null);
  const [hover, setHover] = useState<{ idx: number } | null>(null);
  const [wrapRef, W] = useMeasuredWidth(720);
  const H = height;
  const PL = 46;
  const PR = 10;
  const PT = 12;
  const PB = 22;
  const cw = W - PL - PR;
  const ch = H - PT - PB;
  const n = Math.max(...series.map((s) => s.points.length), 1);
  const max = Math.max(
    1,
    ...series.flatMap((s) => s.points).filter((v): v is number => v != null && Number.isFinite(v)),
  );

  // Position each bucket by its TIMESTAMP across the data's time domain, not by
  // array index. Metrics-v2 (and the RED aggregations) emit only buckets that
  // have data — index spacing would compress outage gaps into a seamless line
  // and make the x-axis nonlinear in time (O11 / O35). Numeric buckets are
  // epoch-ms; string buckets are zone-less backend timestamps parsed as UTC.
  const bucketTs = useMemo(
    () => buckets.map((b) => (typeof b === 'number' ? b : parseUTCTimestamp(b).getTime())),
    [buckets],
  );
  const [t0, t1] = useMemo<[number, number]>(() => {
    let lo = Infinity;
    let hi = -Infinity;
    for (const t of bucketTs) {
      if (!Number.isFinite(t)) continue;
      if (t < lo) lo = t;
      if (t > hi) hi = t;
    }
    return Number.isFinite(lo) ? [lo, hi] : [0, 1];
  }, [bucketTs]);
  const tspan = Math.max(1, t1 - t0);
  // Fall back to index spacing only for degenerate domains (single/equal bucket
  // times, or an unparseable bucket) so a lone point still lands on the axis.
  const X = (i: number) => {
    const t = bucketTs[i];
    if (t1 === t0 || !Number.isFinite(t)) return PL + (cw * i) / Math.max(1, n - 1);
    return PL + ((t - t0) / tspan) * cw;
  };
  const Y = (v: number) => PT + ch - (v / max) * ch;

  // Build a line path that BREAKS at null gaps (starts a fresh subpath after a
  // hole) instead of drawing a straight segment across missing buckets.
  const linePath = (points: Array<number | null>): string => {
    let d = '';
    let pen = false;
    points.forEach((v, i) => {
      if (v == null || !Number.isFinite(v)) {
        pen = false;
        return;
      }
      d += `${d ? ' ' : ''}${pen ? 'L' : 'M'} ${X(i).toFixed(1)},${Y(v).toFixed(1)}`;
      pen = true;
    });
    return d;
  };

  // Area fill as one closed polygon per contiguous run of real points, each
  // dropped to the zero baseline — so gaps read as empty, not filled-through.
  const areaPath = (points: Array<number | null>): string => {
    const baseY = Y(0).toFixed(1);
    let d = '';
    let run: number[] = [];
    const flush = () => {
      if (run.length === 0) return;
      const first = run[0];
      const last = run[run.length - 1];
      let seg = `M ${X(first).toFixed(1)},${baseY}`;
      for (const i of run) seg += ` L ${X(i).toFixed(1)},${Y(points[i] as number).toFixed(1)}`;
      seg += ` L ${X(last).toFixed(1)},${baseY} Z`;
      d += (d ? ' ' : '') + seg;
      run = [];
    };
    points.forEach((v, i) => {
      if (v == null || !Number.isFinite(v)) {
        flush();
        return;
      }
      run.push(i);
    });
    flush();
    return d;
  };

  const yTicks = useMemo(() => {
    const step = niceStep(max / 3);
    const out: number[] = [];
    for (let v = 0; v <= max + 1e-6; v += step) out.push(v);
    return out;
  }, [max]);

  const xTicks: number[] = [];
  for (let i = 0; i < n; i += Math.max(1, Math.floor(n / 6))) xTicks.push(i);

  const onMove = (e: React.MouseEvent<SVGSVGElement>) => {
    const svg = ref.current;
    if (!svg) return;
    const r = svg.getBoundingClientRect();
    const mx = ((e.clientX - r.left) / r.width) * W;
    // Nearest bucket by x-position — buckets are time-spaced, not index-spaced,
    // so map the cursor to the closest one rather than assuming uniform steps.
    let idx = 0;
    let best = Infinity;
    for (let i = 0; i < n; i += 1) {
      const dx = Math.abs(X(i) - mx);
      if (dx < best) {
        best = dx;
        idx = i;
      }
    }
    setHover({ idx });
  };

  return (
    <div ref={wrapRef} className="relative w-full" style={{ height: H }}>
      <svg
        ref={ref}
        viewBox={`0 0 ${W} ${H}`}
        className="w-full h-full block"
        preserveAspectRatio="none"
        onMouseMove={onMove}
        onMouseLeave={() => setHover(null)}
      >
        {yTicks.map((v, i) => (
          <g key={i}>
            <line x1={PL} y1={Y(v)} x2={W - PR} y2={Y(v)} stroke="var(--color-border)" strokeDasharray="2 3" opacity="0.6" />
            <text x={PL - 6} y={Y(v)} fontSize="9" textAnchor="end" dominantBaseline="middle" fill="var(--color-fg-3)" fontFamily="ui-monospace, monospace">
              {yFmt(v)}
            </text>
          </g>
        ))}
        {xTicks.map((i) => (
          <text key={i} x={X(i)} y={H - 6} fontSize="8.5" textAnchor="middle" fill="var(--color-fg-3)" fontFamily="ui-monospace, monospace">
            {hhmm(buckets[i])}
          </text>
        ))}
        {series.map((s, si) => {
          const line = linePath(s.points);
          return (
            <g key={si}>
              {s.fill && <path d={areaPath(s.points)} fill={s.color} opacity="0.12" />}
              <path
                d={line}
                fill="none"
                stroke={s.color}
                strokeWidth={s.dashed ? 1.1 : 1.6}
                strokeDasharray={s.dashed ? '3 3' : undefined}
                strokeLinejoin="round"
                strokeLinecap="round"
                opacity={hover ? 0.95 : 1}
              />
            </g>
          );
        })}
        {markers.map((m, i) => (
          <line
            key={'mk' + i}
            x1={X(m.idx)}
            y1={PT}
            x2={X(m.idx)}
            y2={H - PB}
            stroke="var(--color-fg-3)"
            strokeDasharray="2 2"
            strokeOpacity="0.8"
          />
        ))}
        {hover && (
          <g>
            <line x1={X(hover.idx)} y1={PT} x2={X(hover.idx)} y2={H - PB} stroke="var(--color-fg)" strokeOpacity="0.25" />
            {series.map((s, si) => {
              const v = s.points[hover.idx];
              if (v == null || !Number.isFinite(v)) return null;
              return (
                <circle key={si} cx={X(hover.idx)} cy={Y(v)} r="2.6" fill="var(--color-bg)" stroke={s.color} strokeWidth="1.4" />
              );
            })}
          </g>
        )}
      </svg>
      {markers.map((m, i) => (
        <div
          key={'ml' + i}
          className="absolute pointer-events-none z-20 -translate-x-1/2"
          style={{ left: `${(X(m.idx) / W) * 100}%`, top: 1 }}
        >
          <span className="inline-flex items-center gap-1 px-1 py-px rounded-[2px] bg-foreground/10 border border-border text-[8.5px] font-mono text-fg-2 whitespace-nowrap">
            <GitCommit className="w-[8px] h-[8px]" />
            {m.label}
          </span>
        </div>
      ))}
      {hover && (
        <div
          className="absolute pointer-events-none z-30 rounded-md border border-border-2 bg-card/95 backdrop-blur px-2.5 py-1.5 text-[11px] shadow-lg min-w-[150px]"
          style={{ left: `min(calc(100% - 160px), ${(X(hover.idx) / W) * 100}%)`, top: 4 }}
        >
          <div className="font-mono text-fg-3 mb-1 text-[10px]">{hhmm(buckets[hover.idx])}</div>
          {series.map((s, si) => {
            const v = s.points[hover.idx];
            const gap = v == null || !Number.isFinite(v);
            return (
              <div key={si} className="flex items-center gap-1.5 leading-tight">
                <span className="w-2 h-2 rounded-sm shrink-0" style={{ background: s.color }} />
                <span className="text-fg-2 flex-1">{s.label}</span>
                <span className="font-mono text-fg tabular-nums">
                  {gap ? '–' : `${yFmt(v)}${unit}`}
                </span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// LatencyScatter
// ---------------------------------------------------------------------------

export interface ScatterTrace {
  id: string;
  /** Start time in ms epoch. */
  startTs: number;
  durationMs: number;
  /** Error span count (>0 renders as a danger dot). */
  errors: number;
  /** Root label for the tooltip. */
  root?: string;
}

export interface LatencyScatterProps {
  traces: ScatterTrace[];
  height?: number;
  onPick?: (t: ScatterTrace) => void;
}

const fmtMs = (ms: number): string =>
  ms >= 1000 ? `${(ms / 1000).toFixed(2)}s` : `${ms.toFixed(ms < 10 ? 2 : 1)}ms`;

export function LatencyScatter({ traces, height = 200, onPick }: LatencyScatterProps) {
  const [hover, setHover] = useState<{ i: number; t: ScatterTrace } | null>(null);
  const [wrapRef, W] = useMeasuredWidth(880);
  if (traces.length === 0) {
    return (
      <div className="flex items-center justify-center text-[12px] text-fg-3" style={{ height }}>
        No traces in range.
      </div>
    );
  }
  const H = height;
  const PL = 48;
  const PR = 12;
  const PT = 12;
  const PB = 24;
  const cw = W - PL - PR;
  const ch = H - PT - PB;
  const t0 = Math.min(...traces.map((t) => t.startTs));
  const t1 = Math.max(...traces.map((t) => t.startTs));
  const maxD = Math.max(1, ...traces.map((t) => t.durationMs));
  const sc = (v: number) => Math.sqrt(v / maxD);
  const X = (ts: number) => PL + ((ts - t0) / Math.max(1, t1 - t0)) * cw;
  const Y = (d: number) => PT + ch - sc(d) * ch;

  const yTicks = [0, maxD * 0.04, maxD * 0.16, maxD * 0.5, maxD];

  return (
    <div ref={wrapRef} className="relative w-full" style={{ height: H }}>
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-full block" preserveAspectRatio="none" onMouseLeave={() => setHover(null)}>
        {yTicks.map((v, i) => (
          <g key={i}>
            <line x1={PL} y1={Y(v)} x2={W - PR} y2={Y(v)} stroke="var(--color-border)" strokeDasharray="2 3" opacity="0.6" />
            <text x={PL - 6} y={Y(v)} fontSize="9" textAnchor="end" dominantBaseline="middle" fill="var(--color-fg-3)" fontFamily="ui-monospace, monospace">
              {v >= 1000 ? (v / 1000).toFixed(1) + 's' : Math.round(v) + 'ms'}
            </text>
          </g>
        ))}
        {[0, 0.25, 0.5, 0.75, 1].map((f, i) => (
          <text key={i} x={PL + f * cw} y={H - 6} fontSize="8.5" textAnchor="middle" fill="var(--color-fg-3)" fontFamily="ui-monospace, monospace">
            {hhmm(t0 + f * (t1 - t0))}
          </text>
        ))}
        {traces.map((t, i) => {
          const err = t.errors > 0;
          const r = hover?.i === i ? 4.5 : 3;
          return (
            <circle
              key={t.id}
              cx={X(t.startTs)}
              cy={Y(t.durationMs)}
              r={r}
              fill={err ? 'var(--color-danger)' : 'var(--color-brand)'}
              fillOpacity={hover && hover.i !== i ? 0.3 : 0.78}
              stroke={err ? 'var(--color-danger)' : 'var(--color-brand)'}
              strokeOpacity="0.4"
              style={{ cursor: 'pointer' }}
              onMouseEnter={() => setHover({ i, t })}
              onClick={() => onPick?.(t)}
            />
          );
        })}
      </svg>
      {hover && (
        <div
          className="absolute pointer-events-none z-30 rounded-md border border-border-2 bg-card/95 backdrop-blur px-2.5 py-1.5 text-[11px] shadow-lg"
          style={{ left: `min(calc(100% - 220px), ${((hover.t.startTs - t0) / Math.max(1, t1 - t0)) * 100}%)`, top: 4 }}
        >
          <div className="font-mono text-fg text-[10.5px]">{hover.t.id.slice(0, 16)}…</div>
          <div className="flex items-center gap-2 mt-0.5 text-fg-3">
            {hover.t.root && (
              <>
                <span>{hover.t.root}</span>
                <span className="text-fg-4">·</span>
              </>
            )}
            <span className="font-mono text-fg-2">{fmtMs(hover.t.durationMs)}</span>
            {hover.t.errors > 0 && <span className="text-danger font-mono">{hover.t.errors} err</span>}
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// BudgetBar — SLO error-budget consumed
// ---------------------------------------------------------------------------

export interface BudgetBarProps {
  /** Percent of the error budget consumed (0..>100). */
  consumedPct: number;
}

export function BudgetBar({ consumedPct }: BudgetBarProps) {
  const consumed = Math.min(100, Math.max(0, consumedPct));
  const tone =
    consumedPct >= 100 ? 'var(--color-danger)' : consumedPct >= 75 ? 'var(--color-warn)' : 'var(--color-good)';
  return (
    <div className="relative h-2 rounded-full bg-foreground/10 overflow-hidden">
      <div className="absolute inset-y-0 left-0 rounded-full" style={{ width: `${consumed}%`, background: tone }} />
    </div>
  );
}
