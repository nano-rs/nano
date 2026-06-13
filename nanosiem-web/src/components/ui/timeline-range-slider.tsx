// SPDX-License-Identifier: AGPL-3.0-or-later

import * as React from 'react';
import {
  addDays,
  differenceInCalendarDays,
  endOfMonth,
  format,
  isSameDay,
  startOfMonth,
  startOfToday,
  subDays,
} from 'date-fns';
import { ChevronsLeft, ChevronsRight } from 'lucide-react';
import { cn } from '@/lib/utils';

/* Experimental timeline-style day-range slider (design spike).
   One tick per day, month labels beneath, and a draggable pill over the
   selected span showing the day count. Interactions:
   - drag the pill body to move the range
   - drag either edge to resize
   - drag on empty track to start a fresh selection
   - click a month label to select that whole month
   - « expands the visible window further back in time (» collapses)
   Day-granular by design — the window always ends at today, selection is
   emitted as local-midnight Dates (same shape react-day-picker hands the
   parent picker, which converts to UTC day bounds on Apply). */

interface TimelineRangeSliderProps {
  startDate: Date | undefined;
  endDate: Date | undefined;
  onChange: (start: Date, end: Date) => void;
  /** Mirror of DateTimeRangePicker's cap (NAN-742) — clamps resize/presets. */
  maxRangeDays?: number;
  className?: string;
}

// Default to a tight window: 1–7 day ranges are the common SIEM case and
// need real pixels per day. « steps outward for hunts over longer history.
const ZOOM_LEVELS = [30, 90, 180];

function clamp(n: number, lo: number, hi: number): number {
  return Math.min(hi, Math.max(lo, n));
}

type DragMode = 'move' | 'left' | 'right' | 'create';

export function TimelineRangeSlider({ startDate, endDate, onChange, maxRangeDays, className }: TimelineRangeSliderProps) {
  const today = startOfToday();
  const [windowDays, setWindowDays] = React.useState(ZOOM_LEVELS[0]);
  const [trackWidth, setTrackWidth] = React.useState(0);
  // Local selection override while a drag is in flight, so the pill tracks
  // the pointer even if the parent re-render lags a frame behind onChange.
  const [dragSel, setDragSel] = React.useState<{ s: number; e: number } | null>(null);
  const trackRef = React.useRef<HTMLDivElement>(null);

  const windowStart = subDays(today, windowDays - 1);
  const idxOf = (d: Date) => differenceInCalendarDays(d, windowStart);
  const dayAt = (i: number) => addDays(windowStart, i);

  React.useLayoutEffect(() => {
    const el = trackRef.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setTrackWidth(el.clientWidth));
    ro.observe(el);
    setTrackWidth(el.clientWidth);
    return () => ro.disconnect();
  }, []);

  // If the incoming selection starts before the visible window (e.g. set
  // from the calendar), widen the window so the pill stays on-screen.
  // Capped at ~13 months — beyond that, ticks degrade to sub-pixel noise
  // and the selection just clamps to the window's left edge.
  React.useEffect(() => {
    if (!startDate) return;
    const daysBack = differenceInCalendarDays(today, startDate) + 1;
    if (daysBack > windowDays) {
      const level = ZOOM_LEVELS.find((l) => l >= daysBack);
      setWindowDays(level ?? Math.min(400, daysBack));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [startDate?.getTime()]);

  const propSel = startDate && endDate
    ? {
        s: clamp(Math.min(idxOf(startDate), idxOf(endDate)), 0, windowDays - 1),
        e: clamp(Math.max(idxOf(startDate), idxOf(endDate)), 0, windowDays - 1),
      }
    : null;
  const sel = dragSel ?? propSel;

  // Month segments visible in the window (first/last may be partial).
  const months = React.useMemo(() => {
    const segs: { month: Date; sIdx: number; eIdx: number }[] = [];
    let cursor = windowStart;
    while (differenceInCalendarDays(today, cursor) >= 0) {
      const mEnd = endOfMonth(cursor);
      const segEnd = differenceInCalendarDays(today, mEnd) >= 0 ? mEnd : today;
      segs.push({
        month: startOfMonth(cursor),
        sIdx: differenceInCalendarDays(cursor, windowStart),
        eIdx: differenceInCalendarDays(segEnd, windowStart),
      });
      cursor = addDays(segEnd, 1);
    }
    return segs;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [windowDays, today.getTime()]);

  const emit = React.useCallback(
    (s: number, e: number) => {
      onChange(dayAt(s), dayAt(e));
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [onChange, windowDays, today.getTime()],
  );

  const beginDrag = (mode: DragMode, ev: React.PointerEvent) => {
    const track = trackRef.current;
    if (!track) return;
    ev.preventDefault();
    ev.stopPropagation();
    const rect = track.getBoundingClientRect();
    const dpd = rect.width / windowDays; // px per day
    const cap = maxRangeDays ?? Infinity;
    const anchor = clamp(Math.floor((ev.clientX - rect.left) / dpd), 0, windowDays - 1);
    const s0 = sel?.s ?? anchor;
    const e0 = sel?.e ?? anchor;
    const startX = ev.clientX;
    let last: { s: number; e: number } | null = null;

    const apply = (s: number, e: number) => {
      if (last && last.s === s && last.e === e) return;
      last = { s, e };
      setDragSel({ s, e });
      onChange(addDays(subDays(today, windowDays - 1), s), addDays(subDays(today, windowDays - 1), e));
    };

    if (mode === 'create') apply(anchor, anchor);

    const move = (e2: PointerEvent) => {
      const dd = Math.round((e2.clientX - startX) / dpd);
      if (mode === 'move') {
        const span = e0 - s0;
        const s = clamp(s0 + dd, 0, windowDays - 1 - span);
        apply(s, s + span);
      } else if (mode === 'left') {
        const lo = Number.isFinite(cap) ? Math.max(0, e0 - (cap - 1)) : 0;
        apply(clamp(s0 + dd, lo, e0), e0);
      } else if (mode === 'right') {
        const hi = Number.isFinite(cap) ? Math.min(windowDays - 1, s0 + (cap - 1)) : windowDays - 1;
        apply(s0, clamp(e0 + dd, s0, hi));
      } else {
        const cur = clamp(Math.floor((e2.clientX - rect.left) / dpd), 0, windowDays - 1);
        let s = Math.min(anchor, cur);
        let e = Math.max(anchor, cur);
        if (Number.isFinite(cap) && e - s + 1 > cap) {
          if (cur < anchor) s = e - (cap - 1);
          else e = s + (cap - 1);
        }
        apply(s, e);
      }
    };
    const up = () => {
      window.removeEventListener('pointermove', move);
      window.removeEventListener('pointerup', up);
      setDragSel(null);
    };
    window.addEventListener('pointermove', move);
    window.addEventListener('pointerup', up);
  };

  // Keyboard path (NAN-1431; ARIA/reader pass deferred): ←/→ move the range
  // ±1 day, Shift+← grows a day into history, Shift+→ shrinks from the
  // start, PageUp/PageDown move ±7 days. Clamps mirror the pointer paths —
  // right edge stops at today, growth respects maxRangeDays, and the left
  // edge may run past the window (the auto-expand effect zooms out) up to
  // the same ~400-day ceiling the window itself is capped at.
  const handleKeyDown = (ev: React.KeyboardEvent) => {
    if (!sel) return;
    const cap = maxRangeDays ?? Infinity;
    let { s, e } = sel;
    switch (ev.key) {
      case 'ArrowLeft':
        s -= 1;
        if (!ev.shiftKey) e -= 1;
        break;
      case 'ArrowRight':
        s += 1;
        if (!ev.shiftKey) e += 1;
        break;
      case 'PageUp':
        s -= 7;
        e -= 7;
        break;
      case 'PageDown':
        s += 7;
        e += 7;
        break;
      default:
        return;
    }
    ev.preventDefault();
    if (e > windowDays - 1) {
      // No future: cancel the overflow on both ends so plain moves keep
      // their span instead of compressing against today.
      const over = e - (windowDays - 1);
      s -= over;
      e -= over;
    }
    if (s > e) return; // can't shrink below a single day
    if (e - s + 1 > cap) return; // can't grow past the range cap
    if (windowDays - s > 400) return; // matches the window's max history
    emit(s, e);
  };

  const selectMonth = (seg: { month: Date; sIdx: number; eIdx: number }) => {
    let s = seg.sIdx;
    let e = seg.eIdx;
    if (maxRangeDays !== undefined && e - s + 1 > maxRangeDays) e = s + (maxRangeDays - 1);
    emit(s, e);
  };

  // Zoom targets: « steps to the next-larger window; » steps to the next-
  // smaller one that still contains the current selection (so zooming in
  // can't push the pill off-track and trip the auto-expand effect).
  const selDaysBack = startDate ? differenceInCalendarDays(today, startDate) + 1 : 1;
  const zoomOutTo = ZOOM_LEVELS.find((l) => l > windowDays);
  const zoomInTo = [...ZOOM_LEVELS].reverse().find((l) => l < windowDays && l >= selDaysBack);
  const dpd = trackWidth > 0 ? trackWidth / windowDays : 0;

  // Pill geometry, with a readability floor: very narrow spans render at a
  // minimum width (centered over the real span, clamped to the track) like
  // the reference's overflowing "7" badge.
  let pill: { left: number; width: number; count: number } | null = null;
  if (sel && trackWidth > 0) {
    const rawLeft = sel.s * dpd;
    const rawWidth = (sel.e - sel.s + 1) * dpd;
    const width = Math.max(rawWidth, 28);
    const left = clamp(rawLeft + rawWidth / 2 - width / 2, 0, trackWidth - width);
    pill = { left, width, count: sel.e - sel.s + 1 };
  }

  // Query-cost tint: ≤14d stays neutral, warning fades in over 14→21d, then
  // shifts warning→destructive over 21→45d+. Longer spans scan more daily
  // partitions — the pill color is a "this query will be slower" signal.
  let costStyle: React.CSSProperties | undefined;
  if (pill && pill.count > 14) {
    const s = clamp((pill.count - 14) / 7, 0, 1);
    const hue =
      pill.count <= 21
        ? 'var(--warning)'
        : `color-mix(in oklab, var(--destructive) ${Math.round(clamp((pill.count - 21) / 24, 0, 1) * 100)}%, var(--warning))`;
    costStyle = {
      borderColor: `color-mix(in oklab, ${hue} ${Math.round(45 + 30 * s)}%, var(--border-2))`,
      color: `color-mix(in oklab, ${hue} ${Math.round(80 * s)}%, var(--foreground))`,
      background: `color-mix(in oklab, ${hue} ${Math.round(9 * s)}%, var(--card))`,
    };
  }

  const rangeLabel = React.useMemo(() => {
    if (!startDate || !endDate) return null;
    const yearFmt = startDate.getFullYear() !== today.getFullYear() ? 'MMM d, yyyy' : 'MMM d';
    const startStr = format(startDate, yearFmt);
    const endStr = isSameDay(endDate, today) ? 'Today' : format(endDate, endDate.getFullYear() !== today.getFullYear() ? 'MMM d, yyyy' : 'MMM d');
    return { startStr, endStr };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [startDate?.getTime(), endDate?.getTime(), today.getTime()]);

  return (
    <div className={cn('select-none', className)}>
      {/* header: selected range readout (presets live in the picker sidebar
          and reflect into the pill — the slider carries no presets itself) */}
      <div className="font-mono text-[12px] text-foreground min-w-0 truncate mb-2">
        {rangeLabel ? (
          <>
            <span className="font-semibold">{rangeLabel.startStr}</span>
            <span className="text-muted-foreground/60 mx-1.5">–</span>
            <span className="font-semibold">{rangeLabel.endStr}</span>
          </>
        ) : (
          <span className="text-muted-foreground">Select a range</span>
        )}
      </div>

      {/* timeline row */}
      <div className="flex items-start gap-1.5">
        <button
          onClick={() => zoomOutTo && setWindowDays(zoomOutTo)}
          disabled={!zoomOutTo}
          title="Show more history"
          className="h-9 w-5 shrink-0 inline-flex items-center justify-center rounded text-muted-foreground/70 hover:text-foreground hover:bg-foreground/5 transition-colors disabled:opacity-30 disabled:pointer-events-none"
        >
          <ChevronsLeft className="w-3.5 h-3.5" strokeWidth={1.5} />
        </button>

        <div className="flex-1 min-w-0">
          <div
            ref={trackRef}
            className="relative h-9 cursor-crosshair touch-none"
            onPointerDown={(ev) => beginDrag('create', ev)}
          >
            {/* day ticks */}
            {Array.from({ length: windowDays }).map((_, i) => (
              <div
                key={i}
                className="absolute top-1/2 -translate-y-1/2 w-px h-[15px] rounded-full bg-muted-foreground/30 pointer-events-none"
                style={{ left: `${((i + 0.5) / windowDays) * 100}%` }}
              />
            ))}

            {/* selection pill */}
            {pill && (
              <div
                tabIndex={0}
                className="absolute top-0 bottom-0 rounded-md border border-border-2 bg-card shadow-sm flex items-center justify-center cursor-grab active:cursor-grabbing focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary/60"
                style={{ left: pill.left, width: pill.width, ...costStyle }}
                onPointerDown={(ev) => beginDrag('move', ev)}
                onKeyDown={handleKeyDown}
              >
                <span
                  className="font-mono text-[11px] text-foreground whitespace-nowrap pointer-events-none px-1"
                  style={costStyle ? { color: costStyle.color } : undefined}
                >
                  {pill.width > 70 ? `${pill.count} Days` : pill.count}
                </span>
                <div
                  className="absolute left-0 top-0 bottom-0 w-2 cursor-ew-resize"
                  onPointerDown={(ev) => beginDrag('left', ev)}
                />
                <div
                  className="absolute right-0 top-0 bottom-0 w-2 cursor-ew-resize"
                  onPointerDown={(ev) => beginDrag('right', ev)}
                />
              </div>
            )}
          </div>

          {/* month labels */}
          <div className="relative h-4 mt-0.5">
            {months.map((seg) => {
              const segWidth = (seg.eIdx - seg.sIdx + 1) * dpd;
              if (segWidth < 24) return null;
              const full = format(seg.month, 'MMMM');
              const label = segWidth >= full.length * 6.5 ? full : format(seg.month, 'MMM');
              const inSelection = !!sel && seg.sIdx <= sel.e && seg.eIdx >= sel.s;
              return (
                <button
                  key={seg.month.toISOString()}
                  onClick={() => selectMonth(seg)}
                  className={cn(
                    'absolute -translate-x-1/2 text-[11px] leading-4 whitespace-nowrap transition-colors',
                    inSelection
                      ? 'text-foreground font-medium'
                      : 'text-muted-foreground/60 hover:text-foreground',
                  )}
                  style={{ left: `${(((seg.sIdx + seg.eIdx + 1) / 2) / windowDays) * 100}%` }}
                >
                  {label}
                </button>
              );
            })}
          </div>
        </div>

        <button
          onClick={() => zoomInTo && setWindowDays(zoomInTo)}
          disabled={!zoomInTo}
          title="Zoom in to recent"
          className="h-9 w-5 shrink-0 inline-flex items-center justify-center rounded text-muted-foreground/70 hover:text-foreground hover:bg-foreground/5 transition-colors disabled:opacity-30 disabled:pointer-events-none"
        >
          <ChevronsRight className="w-3.5 h-3.5" strokeWidth={1.5} />
        </button>
      </div>
    </div>
  );
}
