// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-3207: per-log-source health — hourly volume against the seasonal
 * expected band (same hour, previous 7 days), a status, and per-segment
 * (class / product / region / account / service) drill-down so a drop in one
 * slice of a source is visible even when the source total still looks fine.
 *
 * Chart mechanics mirror IngestionActivityChart (NAN-3194): the SVG is drawn
 * at measured pixels (never a stretched viewBox, so axis text stays crisp),
 * with a crosshair + tooltip snapped to the nearest hour. Clicking an hour
 * opens Search scoped to the source (and segment) for that hour.
 *
 * Surfaces:
 *   - `LogSourceHealthList`  — SIEM Health page: one compact row per source,
 *     attention states first, click to expand its segments.
 *   - `LogSourceHealthPanel` — Log Source detail: full chart + segment list;
 *     honours `?segment=<dimension>:<value>` (notification deep links).
 */
import { useLayoutEffect, useMemo, useRef, useState } from 'react';
import type { KeyboardEvent, MouseEvent } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { Activity, ChevronDown, ChevronRight, Search } from 'lucide-react';

import { useLogSourceHealthSeries, useLogSourcesHealthSeries } from '@/hooks/use-log-source-health';
import type {
  BucketAssessment,
  HealthSeriesPoint,
  LogSourceHealthSeries,
  SegmentHealthSeries,
  SourceHealthState,
} from '@/lib/api';
import { formatCompactNumber, formatUTCCompact } from '@/lib/date-utils';
import {
  healthSearchHref,
  healthStateRank,
  hourWindow,
  learningProgress,
  parseSegmentParam,
  segmentKey,
  sortHealthSeries,
} from '@/lib/log-source-health';
import { cn } from '@/lib/utils';

/* ============================================================================
   STATE TOKENS
   ============================================================================ */

// Severity colours are fixed oklch (same values as the SIEM Health page's
// TONE_DOT) so a red "dropped" reads the same on every theme.
const C_ERROR = 'oklch(62% 0.22 18)';
const C_WARN = 'oklch(72% 0.18 28)';
const C_OK = 'oklch(70% 0.16 160)';
const C_VOLUME = 'oklch(70% 0.17 250)';

type StateMeta = { label: string; text: string; bg: string; dot: string };

const HEALTH_STATE_META: Record<SourceHealthState, StateMeta> = {
  segment_drop: { label: 'Segment drop', text: 'text-red-400', bg: 'bg-red-500/10 border-red-500/30', dot: C_ERROR },
  stale: { label: 'Stale', text: 'text-red-400', bg: 'bg-red-500/10 border-red-500/30', dot: C_ERROR },
  degraded: { label: 'Degraded', text: 'text-amber-400', bg: 'bg-amber-500/10 border-amber-500/30', dot: C_WARN },
  healthy: { label: 'Healthy', text: 'text-emerald-400', bg: 'bg-emerald-500/10 border-emerald-500/30', dot: C_OK },
  learning: { label: 'Learning', text: 'text-sky-400', bg: 'bg-sky-500/10 border-sky-500/30', dot: C_VOLUME },
  unknown: { label: 'Unknown', text: 'text-muted-foreground', bg: 'bg-foreground/5 border-border', dot: 'var(--muted-foreground)' },
  disabled: { label: 'Disabled', text: 'text-muted-foreground', bg: 'bg-foreground/5 border-border', dot: 'var(--muted-foreground)' },
};

const ASSESSMENT_LABEL: Record<BucketAssessment, string> = {
  no_baseline: 'no baseline',
  source_silent: 'source silent',
  dropped: 'dropped',
  low: 'below band',
  normal: 'in band',
};

function stateMeta(state: SourceHealthState): StateMeta {
  return HEALTH_STATE_META[state] ?? HEALTH_STATE_META.unknown;
}

/* ============================================================================
   PIECES
   ============================================================================ */

type PillSubject = Pick<LogSourceHealthSeries, 'state' | 'baseline_days' | 'baseline_days_required'>;

/** `subject`: the source or segment (state + baseline progress). */
export function HealthStatePill({ subject }: { subject: PillSubject }) {
  const { state } = subject;
  const m = stateMeta(state);
  // NAN-3246: a no-baseline-yet state reads as learning, with progress.
  const learning = learningProgress(subject);
  return (
    <span
      data-testid="health-state-pill"
      data-state={state}
      title={learning?.long}
      aria-label={learning?.long}
      className={cn(
        'inline-flex h-[18px] shrink-0 items-center gap-1 rounded-sm border px-1.5 font-mono text-[10px] font-semibold uppercase tracking-[0.08em] whitespace-nowrap',
        m.text,
        m.bg,
      )}
    >
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: m.dot }} />
      {m.label}
      {learning?.short && <span className="font-normal normal-case tabular-nums opacity-80">{learning.short}</span>}
    </span>
  );
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

/** Contiguous runs of indices where `ok(i)` holds (null gaps break lines/bands). */
function runs(n: number, ok: (i: number) => boolean): number[][] {
  const out: number[][] = [];
  let cur: number[] = [];
  for (let i = 0; i < n; i++) {
    if (ok(i)) cur.push(i);
    else if (cur.length) {
      out.push(cur);
      cur = [];
    }
  }
  if (cur.length) out.push(cur);
  return out;
}

const TOOLTIP_W = 188;

/**
 * Volume line over the expected band. `compact` drops the axes (row
 * sparklines); the tooltip and click-to-search stay.
 */
export function HealthBandChart({
  points,
  height,
  compact = false,
  label,
  onBucketClick,
}: {
  points: HealthSeriesPoint[];
  height: number;
  compact?: boolean;
  label: string;
  onBucketClick?: (idx: number) => void;
}) {
  const [wrapRef, W] = useMeasuredWidth(compact ? 320 : 960);
  const [hoverIdx, setHoverIdx] = useState<number | null>(null);

  const PAD_L = compact ? 2 : 44;
  const PAD_R = compact ? 2 : 12;
  const PAD_T = compact ? 2 : 6;
  const PAD_B = compact ? 2 : 22;
  const N = points.length;
  const innerW = Math.max(1, W - PAD_L - PAD_R);
  const innerH = Math.max(1, height - PAD_T - PAD_B);
  const maxY = useMemo(
    () => Math.max(1, ...points.map((p) => Math.max(p.events, p.high ?? 0, p.expected ?? 0))),
    [points],
  );
  const xAt = (i: number) => (N <= 1 ? PAD_L + innerW / 2 : PAD_L + (i / (N - 1)) * innerW);
  const yAt = (v: number) => PAD_T + innerH - (v / maxY) * innerH;
  const f = (n: number) => n.toFixed(1);

  const bandPaths = runs(N, (i) => points[i].low != null && points[i].high != null).map((run) => {
    const top = run.map((i, k) => `${k === 0 ? 'M' : 'L'}${f(xAt(i))},${f(yAt(points[i].high as number))}`).join(' ');
    const bot = [...run].reverse().map((i) => `L${f(xAt(i))},${f(yAt(points[i].low as number))}`).join(' ');
    return `${top} ${bot} Z`;
  });
  const expectedPaths = runs(N, (i) => points[i].expected != null).map((run) =>
    run.map((i, k) => `${k === 0 ? 'M' : 'L'}${f(xAt(i))},${f(yAt(points[i].expected as number))}`).join(' '),
  );
  const volumePath = points.map((p, i) => `${i === 0 ? 'M' : 'L'}${f(xAt(i))},${f(yAt(p.events))}`).join(' ');
  const volumeArea = N > 0 ? `${volumePath} L${f(xAt(N - 1))},${f(yAt(0))} L${f(xAt(0))},${f(yAt(0))} Z` : '';
  const slot = N > 1 ? innerW / (N - 1) : innerW;

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
    } else if (e.key === 'Enter' && hoverIdx != null && onBucketClick) {
      onBucketClick(hoverIdx);
    } else if (e.key === 'Escape') {
      setHoverIdx(null);
    }
  };

  if (N === 0) {
    return (
      <div
        className="flex items-center justify-center font-mono text-[10.5px] text-muted-foreground"
        style={{ height }}
      >
        no data
      </div>
    );
  }

  const hoverX = hoverIdx != null ? xAt(hoverIdx) : 0;
  const tooltipLeft =
    hoverIdx == null ? 0 : hoverX + 10 + TOOLTIP_W > W ? Math.max(0, hoverX - 10 - TOOLTIP_W) : hoverX + 10;
  const hp = hoverIdx != null ? points[hoverIdx] : null;
  const hoursBack = Math.max(0, N - 1);

  return (
    <div
      ref={wrapRef}
      data-testid="health-band-chart"
      className={cn(
        'relative w-full min-w-0 outline-none focus-visible:ring-1 focus-visible:ring-ring rounded-sm',
        onBucketClick && 'cursor-pointer',
      )}
      style={{ height }}
      tabIndex={0}
      role="group"
      aria-label={`${label}. Use left and right arrow keys to inspect hours${onBucketClick ? ', Enter to search that hour' : ''}.`}
      onMouseMove={onMouseMove}
      onMouseLeave={() => setHoverIdx(null)}
      onBlur={() => setHoverIdx(null)}
      onKeyDown={onKeyDown}
      onClick={(e) => {
        e.stopPropagation();
        if (onBucketClick && hoverIdx != null) onBucketClick(hoverIdx);
      }}
    >
      <svg width={W} height={height} viewBox={`0 0 ${W} ${height}`} className="block" aria-hidden="true">
        {!compact &&
          [0, 0.5, 1].map((t, i) => {
            const y = PAD_T + innerH - t * innerH;
            return (
              <g key={i}>
                <line x1={PAD_L} x2={W - PAD_R} y1={y} y2={y} stroke="var(--border)" strokeWidth="1" strokeDasharray={i === 0 ? '' : '2,3'} />
                <text
                  data-testid="health-chart-axis-label"
                  x={PAD_L - 6}
                  y={y + 3}
                  textAnchor="end"
                  fontFamily="var(--font-mono, ui-monospace)"
                  fontSize="10.5"
                  fill="var(--muted-foreground)"
                >
                  {formatCompactNumber(Math.round(t * maxY))}
                </text>
              </g>
            );
          })}
        {!compact &&
          [0, 0.25, 0.5, 0.75, 1].map((t, i) => {
            const h = Math.round(hoursBack - t * hoursBack);
            return (
              <text
                key={`x${i}`}
                data-testid="health-chart-axis-label"
                x={PAD_L + t * innerW}
                y={height - 6}
                textAnchor={t === 1 ? 'end' : t === 0 ? 'start' : 'middle'}
                fontFamily="var(--font-mono, ui-monospace)"
                fontSize="10.5"
                fill="var(--muted-foreground)"
              >
                {h === 0 ? 'now' : `-${h}h`}
              </text>
            );
          })}
        {/* Dropped hours: a red wash behind the bucket. */}
        {points.map((p, i) =>
          p.assessment === 'dropped' || p.assessment === 'source_silent' ? (
            <rect
              key={`d${i}`}
              data-testid="health-chart-dropped"
              x={Math.max(PAD_L, xAt(i) - slot / 2)}
              y={PAD_T}
              width={Math.max(1, Math.min(slot, W - PAD_R - Math.max(PAD_L, xAt(i) - slot / 2)))}
              height={innerH}
              fill={C_ERROR}
              fillOpacity="0.14"
            />
          ) : null,
        )}
        {bandPaths.map((d, i) => (
          <path key={`b${i}`} data-testid="health-chart-band" d={d} fill="var(--muted-foreground)" fillOpacity="0.16" stroke="none" />
        ))}
        {expectedPaths.map((d, i) => (
          <path
            key={`e${i}`}
            data-testid="health-chart-expected"
            d={d}
            fill="none"
            stroke="var(--muted-foreground)"
            strokeWidth="1"
            strokeDasharray="3,3"
          />
        ))}
        <path d={volumeArea} fill={C_VOLUME} fillOpacity="0.12" stroke="none" />
        <path data-testid="health-chart-volume" d={volumePath} fill="none" stroke={C_VOLUME} strokeWidth="1.5" strokeLinejoin="round" />
        {points.map((p, i) =>
          p.assessment === 'dropped' || p.assessment === 'low' ? (
            <circle
              key={`m${i}`}
              cx={xAt(i)}
              cy={yAt(p.events)}
              r={compact ? 1.75 : 2.5}
              fill={p.assessment === 'dropped' ? C_ERROR : C_WARN}
            />
          ) : null,
        )}
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
      {hp && (
        <div
          role="tooltip"
          data-testid="health-chart-tooltip"
          className="pointer-events-none absolute top-0 z-10 rounded-md border border-border bg-popover text-popover-foreground shadow-md px-2.5 py-1.5"
          style={{ left: tooltipLeft, width: TOOLTIP_W }}
        >
          <div className="font-mono text-[10.5px] text-muted-foreground tabular-nums pb-1 mb-1 border-b border-border">
            {formatUTCCompact(hp.hour)}
            {hoverIdx === N - 1 && ' · partial'}
          </div>
          <TooltipRow k="Events" v={hp.events.toLocaleString()} />
          <TooltipRow k="Expected" v={hp.expected != null ? hp.expected.toLocaleString() : '—'} />
          <TooltipRow
            k="Band"
            v={hp.low != null && hp.high != null ? `${formatCompactNumber(hp.low)}–${formatCompactNumber(hp.high)}` : '—'}
          />
          <TooltipRow
            k="Status"
            v={hp.assessment ? ASSESSMENT_LABEL[hp.assessment] ?? hp.assessment : 'unsettled'}
            tone={hp.assessment === 'dropped' || hp.assessment === 'source_silent' ? 'text-red-400' : hp.assessment === 'low' ? 'text-amber-400' : undefined}
          />
        </div>
      )}
    </div>
  );
}

function TooltipRow({ k, v, tone }: { k: string; v: string; tone?: string }) {
  return (
    <div className="flex items-center gap-1.5 h-[18px]">
      <span className="text-[11px] text-muted-foreground flex-1">{k}</span>
      <span className={cn('font-mono text-[10.5px] tabular-nums text-foreground', tone)}>{v}</span>
    </div>
  );
}

function Legend() {
  return (
    <div className="flex items-center gap-3 font-mono text-[10px] text-muted-foreground">
      <span className="flex items-center gap-1">
        <span className="inline-block h-[2px] w-3" style={{ background: C_VOLUME }} /> events
      </span>
      <span className="flex items-center gap-1">
        <span className="inline-block h-2 w-3 bg-muted-foreground/20" /> expected band
      </span>
      <span className="flex items-center gap-1">
        <span className="inline-block w-3 border-t border-dashed border-muted-foreground" /> median
      </span>
      <span className="flex items-center gap-1">
        <span className="inline-block h-1.5 w-1.5 rounded-full" style={{ background: C_ERROR }} /> dropped
      </span>
    </div>
  );
}

const DIMENSION_LABEL: Record<string, string> = {
  class: 'class',
  product: 'product',
  region: 'region',
  account: 'account',
  service: 'service',
};

/* ============================================================================
   SEGMENTS
   ============================================================================ */

function SegmentRow({
  source,
  segment,
  expanded,
  highlighted,
  onToggle,
}: {
  source: LogSourceHealthSeries;
  segment: SegmentHealthSeries;
  expanded: boolean;
  highlighted: boolean;
  onToggle: () => void;
}) {
  const navigate = useNavigate();
  const key = segmentKey(segment);
  // The out-of-top-K bucket has no single value to filter on.
  const searchable = !segment.other;
  const hrefFor = (idx?: number) =>
    healthSearchHref(source.source_slugs, {
      field: segment.search_field,
      value: segment.value,
      ...hourWindow(segment.points, idx),
    });

  const rowRef = useRef<HTMLDivElement>(null);
  useLayoutEffect(() => {
    if (highlighted) rowRef.current?.scrollIntoView?.({ block: 'nearest' });
  }, [highlighted]);

  return (
    <div
      ref={rowRef}
      data-testid="health-segment-row"
      data-segment={key}
      data-highlighted={highlighted || undefined}
      data-expanded={expanded || undefined}
      className={cn('border-b border-border last:border-b-0', highlighted && 'bg-accent/40')}
    >
      <div className="flex h-7 items-center gap-2 px-3">
        <button
          type="button"
          onClick={onToggle}
          aria-expanded={expanded}
          aria-label={`${expanded ? 'Collapse' : 'Expand'} ${segment.dimension} ${segment.value}`}
          className="flex min-w-0 shrink-0 items-center gap-1.5 text-left hover:text-foreground"
          style={{ width: 280 }}
        >
          {expanded ? (
            <ChevronDown className="h-3 w-3 shrink-0 text-muted-foreground" strokeWidth={1.5} />
          ) : (
            <ChevronRight className="h-3 w-3 shrink-0 text-muted-foreground" strokeWidth={1.5} />
          )}
          <span className="w-[52px] shrink-0 font-mono text-[10px] uppercase tracking-[0.08em] text-muted-foreground">
            {DIMENSION_LABEL[segment.dimension] ?? segment.dimension}
          </span>
          <span className={cn('truncate font-mono text-[11px] text-foreground', segment.other && 'text-muted-foreground italic')}>
            {segment.value}
          </span>
        </button>
        <span className="w-[124px] shrink-0">
          {segment.other ? (
            <span className="font-mono text-[10px] text-muted-foreground">not judged</span>
          ) : (
            <HealthStatePill subject={segment} />
          )}
        </span>
        <div className="min-w-0 flex-1">
          {!expanded && (
            <HealthBandChart
              points={segment.points}
              height={22}
              compact
              label={`${segment.dimension} ${segment.value} volume`}
              onBucketClick={searchable ? (i) => navigate(hrefFor(i)) : undefined}
            />
          )}
        </div>
        <span className="w-[64px] shrink-0 text-right font-mono text-[10.5px] tabular-nums text-foreground">
          {formatCompactNumber(segment.window_events)}
        </span>
        <span className="w-[120px] shrink-0 truncate text-right font-mono text-[10.5px] tabular-nums text-red-400">
          {segment.dropped_since ? `since ${formatUTCCompact(segment.dropped_since)}` : ''}
        </span>
        <span className="flex w-5 shrink-0 justify-end">
          {searchable && (
            <Link
              to={hrefFor()}
              title={`Search ${segment.search_field}="${segment.value}"`}
              aria-label={`Search ${segment.search_field} ${segment.value}`}
              data-testid="health-segment-search"
              className="text-muted-foreground hover:text-foreground"
            >
              <Search className="h-3 w-3" strokeWidth={1.5} />
            </Link>
          )}
        </span>
      </div>
      {expanded && (
        <div className="px-3 pb-2">
          <HealthBandChart
            points={segment.points}
            height={120}
            label={`${segment.dimension} ${segment.value} volume against expected band`}
            onBucketClick={searchable ? (i) => navigate(hrefFor(i)) : undefined}
          />
        </div>
      )}
    </div>
  );
}

function SegmentList({
  source,
  highlightKey,
  expandedKeys,
  onToggle,
}: {
  source: LogSourceHealthSeries;
  highlightKey?: string | null;
  expandedKeys: Set<string>;
  onToggle: (key: string) => void;
}) {
  if (!source.segments_available) {
    return (
      <div data-testid="health-segments-unavailable" className="px-3 py-2 text-[11px] text-muted-foreground">
        Segment counts are unavailable for this source right now; totals above are still current.
      </div>
    );
  }
  if (!source.segments.length) {
    return <div className="px-3 py-2 text-[11px] text-muted-foreground">No segments observed in this window.</div>;
  }
  return (
    <div data-testid="health-segment-list">
      {source.segments.map((seg) => {
        const key = segmentKey(seg);
        return (
          <SegmentRow
            key={key}
            source={source}
            segment={seg}
            expanded={expandedKeys.has(key)}
            highlighted={highlightKey === key}
            onToggle={() => onToggle(key)}
          />
        );
      })}
    </div>
  );
}

function toggled(set: Set<string>, key: string): Set<string> {
  const next = new Set(set);
  if (next.has(key)) next.delete(key);
  else next.add(key);
  return next;
}

/* ============================================================================
   SIEM HEALTH: ALL SOURCES
   ============================================================================ */

function SourceRow({
  source,
  expanded,
  onToggle,
}: {
  source: LogSourceHealthSeries;
  expanded: boolean;
  onToggle: () => void;
}) {
  const navigate = useNavigate();
  const [expandedSegs, setExpandedSegs] = useState<Set<string>>(() => new Set());
  const total = source.points.reduce((a, p) => a + p.events, 0);
  const drops = source.segments.filter((s) => !s.other && s.state === 'segment_drop').length;

  return (
    <div
      data-testid="health-source-row"
      data-source={source.log_source_id}
      data-state={source.state}
      className="border-b border-border last:border-b-0"
    >
      <div
        role="button"
        tabIndex={0}
        aria-expanded={expanded}
        onClick={onToggle}
        onKeyDown={(e) => {
          if (e.target !== e.currentTarget) return;
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            onToggle();
          }
        }}
        className="flex h-7 cursor-pointer items-center gap-2 px-3 hover:bg-foreground/[0.03] focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
      >
        {expanded ? (
          <ChevronDown className="h-3 w-3 shrink-0 text-muted-foreground" strokeWidth={1.5} />
        ) : (
          <ChevronRight className="h-3 w-3 shrink-0 text-muted-foreground" strokeWidth={1.5} />
        )}
        <div className="flex min-w-0 shrink-0 items-baseline gap-1.5" style={{ width: 260 }}>
          <Link
            to={`/ingestion/log-sources/${encodeURIComponent(source.log_source_id)}`}
            onClick={(e) => e.stopPropagation()}
            className="truncate text-[12px] text-foreground hover:underline"
          >
            {source.log_source_name}
          </Link>
          {source.source_slugs[0] && (
            <span className="truncate font-mono text-[10.5px] text-muted-foreground">{source.source_slugs.join(', ')}</span>
          )}
        </div>
        <span className="w-[124px] shrink-0">
          <HealthStatePill subject={source} />
        </span>
        <div className="min-w-0 flex-1">
          <HealthBandChart
            points={source.points}
            height={22}
            compact
            label={`${source.log_source_name} volume`}
            onBucketClick={(i) => navigate(healthSearchHref(source.source_slugs, hourWindow(source.points, i)))}
          />
        </div>
        <span className="w-[64px] shrink-0 text-right font-mono text-[10.5px] tabular-nums text-foreground">
          {formatCompactNumber(total)}
        </span>
        <span className="w-[120px] shrink-0 truncate text-right font-mono text-[10.5px] tabular-nums text-muted-foreground">
          {drops > 0 ? (
            <span className="text-red-400">
              {drops} segment{drops === 1 ? '' : 's'} down
            </span>
          ) : source.last_event_at ? (
            formatUTCCompact(source.last_event_at)
          ) : (
            '—'
          )}
        </span>
      </div>
      {expanded && (
        <div className="ml-5 border-l border-t border-border">
          <SegmentList
            source={source}
            expandedKeys={expandedSegs}
            onToggle={(k) => setExpandedSegs((s) => toggled(s, k))}
          />
        </div>
      )}
    </div>
  );
}

/** Presentational list (exported for tests and for callers that already have the data). */
export function LogSourceHealthRows({ series }: { series: LogSourceHealthSeries[] }) {
  const sorted = useMemo(() => sortHealthSeries(series), [series]);
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set());
  if (!sorted.length) {
    return <div className="px-3 py-4 text-[11.5px] text-muted-foreground">No log sources to show.</div>;
  }
  return (
    <div data-testid="health-source-list">
      {sorted.map((s) => (
        <SourceRow
          key={s.log_source_id}
          source={s}
          expanded={expanded.has(s.log_source_id)}
          onToggle={() => setExpanded((cur) => toggled(cur, s.log_source_id))}
        />
      ))}
    </div>
  );
}

export function LogSourceHealthList({ hours = 24 }: { hours?: number }) {
  const { data, error, isLoading } = useLogSourcesHealthSeries(hours);
  const counts = useMemo(() => {
    const c = { attention: 0, total: data?.length ?? 0 };
    for (const s of data ?? []) if (healthStateRank(s.state) <= 2) c.attention += 1;
    return c;
  }, [data]);

  return (
    <section
      data-testid="log-source-health-section"
      aria-label="Log source health"
      className="rounded-md border border-border bg-card min-w-0"
    >
      <div className="flex h-9 items-center gap-2 border-b border-border px-3">
        <Activity className="h-3.5 w-3.5 text-muted-foreground" strokeWidth={1.5} />
        <span className="text-[12px] font-medium text-foreground">Log source health</span>
        <span className="font-mono text-[10.5px] text-muted-foreground">· {hours}h · volume vs expected band</span>
        <span className="flex-1" />
        {data && (
          <span className="font-mono text-[10.5px] tabular-nums text-muted-foreground">
            <span className={counts.attention ? 'text-red-400' : 'text-foreground'}>{counts.attention}</span> need attention
            {' · '}
            <span className="text-foreground">{counts.total}</span> sources
          </span>
        )}
      </div>
      {isLoading ? (
        <div className="px-3 py-4 font-mono text-[10.5px] text-muted-foreground">loading…</div>
      ) : error ? (
        <div className="px-3 py-4 text-[11.5px] text-muted-foreground">Log source health is unavailable.</div>
      ) : (
        <>
          <LogSourceHealthRows series={data ?? []} />
          <div className="border-t border-border px-3 py-1.5">
            <Legend />
          </div>
        </>
      )}
    </section>
  );
}

/* ============================================================================
   LOG SOURCE DETAIL: ONE SOURCE
   ============================================================================ */

/** Presentational panel (exported for tests). */
export function LogSourceHealthView({
  source,
  highlightSegment,
}: {
  source: LogSourceHealthSeries;
  highlightSegment?: string | null;
}) {
  const navigate = useNavigate();
  const [expandedSegs, setExpandedSegs] = useState<Set<string>>(() =>
    highlightSegment ? new Set([highlightSegment]) : new Set(),
  );
  // A notification link can land after the panel mounted (same page, new param).
  const [seenHighlight, setSeenHighlight] = useState(highlightSegment);
  if (highlightSegment !== seenHighlight) {
    setSeenHighlight(highlightSegment);
    if (highlightSegment && !expandedSegs.has(highlightSegment)) {
      setExpandedSegs(new Set([...expandedSegs, highlightSegment]));
    }
  }
  const total = source.points.reduce((a, p) => a + p.events, 0);

  return (
    <section
      data-testid="log-source-health-panel"
      aria-label="Source health"
      className="rounded-md border border-border bg-card min-w-0"
    >
      <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1 border-b border-border px-4 py-2">
        <span className="font-mono text-[10.5px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">Health</span>
        <span className="text-[12px] font-semibold text-foreground">Volume vs expected</span>
        <span className="font-mono text-[10.5px] text-muted-foreground">· {source.window_hours}h</span>
        <HealthStatePill subject={source} />
        <span className="flex-1" />
        <span className="font-mono text-[10.5px] tabular-nums text-muted-foreground">
          <span className="text-foreground">{formatCompactNumber(total)}</span> events
          {' · last '}
          <span className="text-foreground">{source.last_event_at ? formatUTCCompact(source.last_event_at) : '—'}</span>
        </span>
      </div>
      <div className="px-2 pt-2">
        <HealthBandChart
          points={source.points}
          height={150}
          label={`${source.log_source_name} volume against expected band`}
          onBucketClick={(i) => navigate(healthSearchHref(source.source_slugs, hourWindow(source.points, i)))}
        />
      </div>
      <div className="px-3 py-1.5">
        <Legend />
      </div>
      <div className="flex h-7 items-center gap-2 border-y border-border bg-card/40 px-3">
        <span className="font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">Segments</span>
        {source.segments_available && (
          <span className="font-mono text-[10.5px] tabular-nums text-muted-foreground">· {source.segments.length}</span>
        )}
      </div>
      <SegmentList
        source={source}
        highlightKey={highlightSegment}
        expandedKeys={expandedSegs}
        onToggle={(k) => setExpandedSegs((s) => toggled(s, k))}
      />
    </section>
  );
}

export function LogSourceHealthPanel({ logSourceId, hours = 24 }: { logSourceId: string; hours?: number }) {
  const [params] = useSearchParams();
  const highlight = parseSegmentParam(params.get('segment'));
  const { data, error, isLoading } = useLogSourceHealthSeries(logSourceId, hours);

  if (isLoading) {
    return (
      <div className="rounded-md border border-border bg-card px-4 py-4 font-mono text-[10.5px] text-muted-foreground">
        loading health…
      </div>
    );
  }
  if (error || !data) {
    return (
      <div
        data-testid="log-source-health-unavailable"
        className="rounded-md border border-border bg-card px-4 py-4 text-[11.5px] text-muted-foreground"
      >
        Source health is unavailable for this source.
      </div>
    );
  }
  return <LogSourceHealthView source={data} highlightSegment={highlight} />;
}
