// SPDX-License-Identifier: AGPL-3.0-or-later

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Hash, Globe, SlidersHorizontal } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Slider } from '@/components/ui/slider';

export interface PrevalenceScatterPoint {
  artifact: string;
  artifactType: 'hash' | 'domain';
  hostCount: number;
  firstSeen: Date;
  lastSeen: Date;
  totalOccurrences: number;
  isRare: boolean;
  prevalenceScore: number;
  envFirstSeen?: Date;
  // NAN-1700: prevalence not yet loaded for this artifact — plotted at its event
  // time on the baseline while the (slow) rarity lookup runs, then enriched.
  pending?: boolean;
}

export interface PrevalenceScatterData {
  hashPoints: PrevalenceScatterPoint[];
  domainPoints: PrevalenceScatterPoint[];
  rarityThreshold: number;
  maxArtifactHostCount?: number;
  totalUnfilteredArtifacts?: number;
}

interface PrevalenceScatterPlotProps {
  data: PrevalenceScatterData;
  onSelectionChange?: (selectedArtifacts: string[]) => void;
  onArtifactClick?: (artifact: string, artifactType: 'hash' | 'domain', timestamp?: Date) => void;
  height?: number;
  loading?: boolean;
  defaultMaxHostCount?: number;
  timeRange?: { start: string; end: string };
  onMaxHostCountChange?: (maxHostCount: number) => void;
}

interface RarityDot {
  artifact: string;
  artifactType: 'hash' | 'domain';
  firstSeen: Date;
  hostCount: number;
  events: number;
  isRare: boolean;
  envFirstSeen?: Date;
  pending?: boolean;
}

interface TipState {
  d: RarityDot;
  px: number;
  py: number;
}

// Plot padding — pixel coords inside the SVG (viewBox = container size so no stretch).
const PL = 60;
const PR = 16;
const PT = 14;
const PB = 32;

// NAN-1696: rarity is a 3-tier scale, not binary. `rare` (< rarity threshold) is
// the hunt signal; anything at/above the threshold used to be flatly labeled
// "common", but a handful of hosts isn't common — it's "uncommon". Reserve
// "common" for artifacts genuinely spread across the fleet.
const COMMON_HOST_THRESHOLD = 20;
// Novelty (independent of rarity): an artifact first seen in the environment
// within this window is "new to the estate" — a real, stable signal, unlike the
// transient host_count-0 state. Surfaced as a subtle ring.
const NOVEL_WINDOW_MS = 48 * 60 * 60 * 1000;

const fmtUtc = (d: Date) => {
  const month = d.toLocaleString('en-US', { month: 'short', timeZone: 'UTC' });
  const day = d.getUTCDate();
  const hh = d.getUTCHours().toString().padStart(2, '0');
  const mm = d.getUTCMinutes().toString().padStart(2, '0');
  return `${month} ${day}, ${hh}:${mm} UTC`;
};

export function PrevalenceScatterPlot({
  data,
  onArtifactClick,
  height = 180,
  loading = false,
  defaultMaxHostCount = 10,
  timeRange,
  onMaxHostCountChange,
}: PrevalenceScatterPlotProps) {
  const plotRef = useRef<HTMLDivElement>(null);
  const [tip, setTip] = useState<TipState | null>(null);
  const [width, setWidth] = useState(1000);
  const [maxHostCount, setMaxHostCount] = useState(defaultMaxHostCount);
  const hostCountDebounceRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  // Debounced callback for asset mode — fires only after user stops dragging.
  const debouncedHostCountChange = useCallback(
    (value: number) => {
      if (!onMaxHostCountChange) return;
      if (hostCountDebounceRef.current) clearTimeout(hostCountDebounceRef.current);
      hostCountDebounceRef.current = setTimeout(() => {
        onMaxHostCountChange(value);
      }, 400);
    },
    [onMaxHostCountChange]
  );
  useEffect(() => () => {
    if (hostCountDebounceRef.current) clearTimeout(hostCountDebounceRef.current);
  }, []);

  useEffect(() => {
    const el = plotRef.current;
    if (!el) return;
    const ro = new ResizeObserver((entries) => {
      const w = entries[0]?.contentRect.width;
      if (w && w > 0) setWidth(Math.round(w));
    });
    ro.observe(el);
    setWidth(Math.max(1, Math.round(el.getBoundingClientRect().width)));
    return () => ro.disconnect();
  }, []);

  const W = width;
  const H = height;
  const PLOT_W = Math.max(1, W - PL - PR);
  const PLOT_H = Math.max(1, H - PT - PB);

  // Dedupe by artifact — one dot per unique artifact, sum events.
  const dots: RarityDot[] = useMemo(() => {
    const map = new Map<string, RarityDot>();
    const ingest = (p: PrevalenceScatterPoint) => {
      const key = `${p.artifactType}::${p.artifact}`;
      const existing = map.get(key);
      if (existing) {
        existing.events += p.totalOccurrences || 1;
        if (p.firstSeen < existing.firstSeen) existing.firstSeen = p.firstSeen;
        if (!p.pending) existing.pending = false;
      } else {
        map.set(key, {
          artifact: p.artifact,
          artifactType: p.artifactType,
          firstSeen: p.firstSeen,
          hostCount: Number.isFinite(p.hostCount) && p.hostCount >= 0 ? p.hostCount : 0,
          events: p.totalOccurrences || 1,
          isRare: p.isRare,
          envFirstSeen: p.envFirstSeen,
          pending: p.pending,
        });
      }
    };
    data.hashPoints.forEach(ingest);
    data.domainPoints.forEach(ingest);
    return Array.from(map.values());
  }, [data]);

  // Filter by host count slider — tunes out noisy / common artifacts.
  const filteredDots = useMemo(
    () => dots.filter((d) => d.hostCount <= maxHostCount),
    [dots, maxHostCount]
  );

  // Logarithmic slider: lots of precision at 1–100, still reaches 10k+ at the top.
  // Internal position is 0–1000 (linear), mapped to 1–maxPossible (log).
  const maxPossibleHostCount = useMemo(() => {
    if (data.maxArtifactHostCount) return Math.max(data.maxArtifactHostCount, 1000);
    const all = [...data.hashPoints, ...data.domainPoints].map((p) => p.hostCount);
    return Math.max(...all, 1000);
  }, [data]);
  const LOG_STEPS = 1000;
  const hostCountToSlider = useCallback(
    (count: number) => {
      if (count <= 1) return 0;
      if (count >= maxPossibleHostCount) return LOG_STEPS;
      return Math.round((LOG_STEPS * Math.log(count)) / Math.log(maxPossibleHostCount));
    },
    [maxPossibleHostCount]
  );
  const sliderToHostCount = useCallback(
    (pos: number) => {
      if (pos <= 0) return 1;
      if (pos >= LOG_STEPS) return maxPossibleHostCount;
      return Math.round(Math.pow(maxPossibleHostCount, pos / LOG_STEPS));
    },
    [maxPossibleHostCount]
  );

  // X domain: prefer explicit search time range, else span the dots.
  const [xMin, xMax] = useMemo<[number, number]>(() => {
    if (timeRange?.start && timeRange?.end) {
      const s = new Date(timeRange.start).getTime();
      const e = new Date(timeRange.end).getTime();
      if (!isNaN(s) && !isNaN(e) && e > s) return [s, e];
    }
    if (filteredDots.length > 0) {
      // NAN-1695: X-axis is EVENT TIME — plot each rare artifact at when it occurred
      // in the search window (the IR/SecOps asset-timeline pattern: rare activity pops
      // at the moment it fired). The environment first-seen is context in the tooltip,
      // NOT the axis — moving an old-but-rare artifact to its months-ago debut would
      // push it off the investigation window and lose the "when did it fire" signal.
      const times = filteredDots.map((d) => d.firstSeen.getTime());
      const lo = Math.min(...times);
      const hi = Math.max(...times);
      if (hi > lo) return [lo, hi];
      const pad = 3600_000;
      return [lo - pad, hi + pad];
    }
    const now = Date.now();
    return [now - 24 * 3600_000, now];
  }, [timeRange, filteredDots]);

  // Y axis (log): 1, 10, 100, 1k, 10k. Ceiling up to next power of 10 above the slider cap
  // so the visible range doesn't collapse as the analyst dials down to rare.
  const yMax = useMemo(() => {
    const cap = Math.max(maxHostCount, 1);
    return Math.pow(10, Math.max(1, Math.ceil(Math.log10(cap + 1))));
  }, [maxHostCount]);

  const yTicks = useMemo(() => {
    const ticks: number[] = [];
    for (let v = 1; v <= yMax; v *= 10) ticks.push(v);
    return ticks;
  }, [yMax]);

  const xTickCount = 6;
  const xTicks = useMemo(() => {
    const out: number[] = [];
    for (let i = 0; i <= xTickCount; i++) {
      out.push(xMin + ((xMax - xMin) * i) / xTickCount);
    }
    return out;
  }, [xMin, xMax]);

  // Scales — X linear over time, Y log over host count (clamped to 0.5 so 0 still renders).
  const xScale = (t: number) => PL + ((t - xMin) / (xMax - xMin)) * PLOT_W;
  const yScale = (v: number) => {
    const logMin = Math.log10(0.5);
    const logMax = Math.log10(yMax);
    const logV = Math.log10(Math.max(v, 0.5));
    return PT + PLOT_H - ((logV - logMin) / (logMax - logMin)) * PLOT_H;
  };

  // Rare zone = hostCount < rarityThreshold. Clamped display cap prevents
  // API-corrupted threshold values from eating the whole plot.
  const safeThreshold = Math.min(Math.max(data.rarityThreshold, 1), 1000);
  const rareZoneTop = yScale(safeThreshold);
  const rareZoneBottom = PT + PLOT_H;
  const rareZoneH = Math.max(0, rareZoneBottom - rareZoneTop);
  const nowMs = Date.now(); // for the novelty ring (first-seen recency)

  const rangeMs = xMax - xMin;
  const fmtXTick = (t: number) => {
    const d = new Date(t);
    const month = d.toLocaleString('en-US', { month: 'short', timeZone: 'UTC' });
    const day = d.getUTCDate();
    const hh = d.getUTCHours().toString().padStart(2, '0');
    const mm = d.getUTCMinutes().toString().padStart(2, '0');
    if (rangeMs <= 4 * 3600_000) return `${hh}:${mm}`;
    if (rangeMs <= 24 * 3600_000) return `${hh}:${mm}`;
    return `${month} ${day}`;
  };
  const fmtYTick = (v: number) => (v >= 1000 ? `${v / 1000}k` : `${v}`);

  const handleEnter = (d: RarityDot, cx: number, cy: number) => {
    // viewBox matches container pixel dimensions, so cx/cy are already container-local pixels.
    setTip({ d, px: cx, py: cy });
  };

  const totalArtifacts = dots.length;
  const shownArtifacts = filteredDots.length;

  return (
    <div ref={plotRef} className="relative font-mono" style={{ height }}>
      {/* Compact host-count slider — tunes out common artifacts. Top-left so it
          doesn't collide with the COMMON · BASELINE legend in the top-right corner. */}
      <div className="absolute left-[66px] top-1 z-[5] flex items-center gap-2 rounded-md border border-border bg-foreground/[0.03] px-2 py-1">
        <SlidersHorizontal className="w-3 h-3 text-muted-foreground" />
        <span className="text-[10.5px] tabular-nums text-muted-foreground whitespace-nowrap min-w-[62px]">
          ≤{maxHostCount.toLocaleString()} hosts
        </span>
        <Slider
          value={[hostCountToSlider(maxHostCount)]}
          onValueChange={(v) => {
            const hc = sliderToHostCount(v[0]);
            setMaxHostCount(hc);
            debouncedHostCountChange(hc);
          }}
          min={0}
          max={LOG_STEPS}
          step={1}
          className="w-24"
        />
      </div>
      <svg
        viewBox={`0 0 ${W} ${H}`}
        width={W}
        height={H}
        className="block overflow-visible"
      >
        {/* Rare zone — tinted band where hostCount < threshold */}
        {rareZoneH > 0 && (
          <rect
            x={PL}
            y={rareZoneTop}
            width={PLOT_W}
            height={rareZoneH}
            style={{ fill: 'var(--primary)', opacity: 0.1 }}
          />
        )}
        {/* NAN-1696: dashed rarity-threshold boundary — everything below this
            line (on <safeThreshold hosts) is "rare". Makes the cutoff explicit
            instead of implying it via the band edge. */}
        {rareZoneH > 0 && (
          <line
            x1={PL}
            x2={PL + PLOT_W}
            y1={rareZoneTop}
            y2={rareZoneTop}
            stroke="var(--primary)"
            strokeWidth="1"
            strokeDasharray="4 3"
            strokeOpacity="0.5"
          />
        )}

        {/* Zone labels */}
        <text
          x={PL + 6}
          y={rareZoneBottom - 6}
          fontSize="9"
          fontFamily="Geist Mono"
          letterSpacing="0.12em"
          fontWeight="600"
          opacity="0.7"
          style={{ fill: 'var(--primary)' }}
        >
          {`RARE · < ${safeThreshold} HOST${safeThreshold === 1 ? '' : 'S'}`}
        </text>
        <text
          x={W - PR - 6}
          y={PT + 12}
          textAnchor="end"
          fontSize="9"
          fontFamily="Geist Mono"
          letterSpacing="0.12em"
          fontWeight="600"
          opacity="0.7"
          style={{ fill: 'var(--muted-foreground)' }}
        >
          COMMON · BASELINE
        </text>

        {/* Grid lines */}
        {yTicks.map((v) => (
          <line
            key={`gy-${v}`}
            x1={PL}
            x2={W - PR}
            y1={yScale(v)}
            y2={yScale(v)}
            style={{ stroke: 'var(--foreground)', opacity: 0.06 }}
          />
        ))}
        {xTicks.map((t, i) =>
          i === 0 || i === xTicks.length - 1 ? null : (
            <line
              key={`gx-${i}`}
              x1={xScale(t)}
              x2={xScale(t)}
              y1={PT}
              y2={PT + PLOT_H}
              style={{ stroke: 'var(--foreground)', opacity: 0.06 }}
            />
          )
        )}

        {/* Axes */}
        <line
          x1={PL}
          x2={W - PR}
          y1={PT + PLOT_H}
          y2={PT + PLOT_H}
          style={{ stroke: 'var(--foreground)', opacity: 0.12 }}
        />
        <line
          x1={PL}
          x2={PL}
          y1={PT}
          y2={PT + PLOT_H}
          style={{ stroke: 'var(--foreground)', opacity: 0.12 }}
        />

        {/* X tick labels */}
        {xTicks.map((t, i) => (
          <text
            key={`tx-${i}`}
            x={xScale(t)}
            y={PT + PLOT_H + 14}
            textAnchor="middle"
            fontSize="9.5"
            fontFamily="Geist Mono"
            style={{ fill: 'var(--muted-foreground)' }}
          >
            {fmtXTick(t)}
          </text>
        ))}
        {/* Y tick labels */}
        {yTicks.map((v) => (
          <text
            key={`ty-${v}`}
            x={PL - 8}
            y={yScale(v) + 3}
            textAnchor="end"
            fontSize="9.5"
            fontFamily="Geist Mono"
            style={{ fill: 'var(--muted-foreground)' }}
          >
            {fmtYTick(v)}
          </text>
        ))}

        {/* Axis titles */}
        <text
          x={(PL + W - PR) / 2}
          y={H - 4}
          textAnchor="middle"
          fontSize="9.5"
          fontFamily="Geist Mono"
          letterSpacing="0.12em"
          fontWeight="600"
          style={{ fill: 'var(--muted-foreground)' }}
        >
          EVENT TIME · UTC
        </text>
        <text
          x={10}
          y={PT + PLOT_H / 2}
          transform={`rotate(-90 10 ${PT + PLOT_H / 2})`}
          textAnchor="middle"
          fontSize="9.5"
          fontFamily="Geist Mono"
          letterSpacing="0.12em"
          fontWeight="600"
          style={{ fill: 'var(--muted-foreground)' }}
        >
          HOSTS
        </text>

        {/* Dots */}
        {filteredDots.map((d) => {
          const cx = xScale(d.firstSeen.getTime()); // NAN-1695: event time (occurrence in window)
          const cy = yScale(Math.max(d.hostCount, 0.8));
          const r = Math.max(3, Math.min(9, Math.log10(d.events + 1) * 2.2));
          // Rarity opacity: rare pops, uncommon is present, common recedes hard,
          // and an unbaselined (host_count 0 / no prevalence) dot recedes too — we
          // have no signal, so don't draw the eye to it (NAN-1699). Common are
          // kept very faint so they're visible-but-quiet when the slider is widened.
          const recede = d.hostCount >= COMMON_HOST_THRESHOLD || d.hostCount === 0;
          const fillOpacity = d.isRare ? 1 : recede ? 0.15 : 0.6;
          const strokeOpacity = d.isRare ? 0.9 : recede ? 0.1 : 0.4;
          // Novelty ring: first seen in the env within the window. Gated to rare +
          // uncommon only — "new to env" is the actionable cue where spread is low;
          // on common (20+ hosts) it's just noise, so we keep those dots quiet.
          const isNovel =
            !d.pending &&
            d.hostCount > 0 &&
            d.hostCount < COMMON_HOST_THRESHOLD &&
            d.envFirstSeen != null &&
            nowMs - d.envFirstSeen.getTime() < NOVEL_WINDOW_MS;
          // NAN-1700 progressive render: while prevalence is loading, the dot is
          // plotted at its event time on the baseline (host_count 0) in a muted,
          // pulsing "scoring…" state. When the lookup lands it animates up to its
          // real rarity Y and colorizes — the transition on cy/fill does the reveal.
          const dotFill = d.pending
            ? 'var(--muted-foreground)'
            : d.isRare
            ? 'var(--primary)'
            : 'var(--foreground)';
          return (
            <g
              key={`${d.artifactType}-${d.artifact}`}
              className="cursor-pointer"
              onMouseEnter={() => handleEnter(d, cx, cy)}
              onMouseLeave={() => setTip(null)}
              onClick={() => onArtifactClick?.(d.artifact, d.artifactType, d.firstSeen)}
            >
              {/* first-seen-recently ring — "new to the environment". Softer on
                  uncommon than rare, so the cue tracks the underlying rarity. */}
              {isNovel && (
                <circle
                  cx={cx}
                  cy={cy}
                  r={r + 3.5}
                  fill="none"
                  stroke="var(--primary)"
                  strokeWidth="1"
                  strokeOpacity={d.isRare ? 0.55 : 0.3}
                />
              )}
              <circle
                cx={cx}
                cy={cy}
                r={r}
                strokeWidth="1"
                style={{
                  fill: dotFill,
                  fillOpacity: d.pending ? 0.4 : fillOpacity,
                  stroke: dotFill,
                  strokeOpacity: d.pending ? 0.25 : strokeOpacity,
                  transition:
                    'r 0.3s ease, cy 0.6s ease, cx 0.4s ease, fill 0.5s ease, fill-opacity 0.5s ease, stroke-opacity 0.5s ease',
                }}
                className={cn(d.pending && 'animate-pulse', !d.pending && d.isRare && 'rare-glow')}
              />
            </g>
          );
        })}
      </svg>

      {/* Loading / empty state overlays */}
      {loading && totalArtifacts === 0 && (
        <div className="absolute inset-0 flex items-center justify-center text-xs text-muted-foreground">
          Loading rarity index…
        </div>
      )}
      {!loading && totalArtifacts === 0 && (
        <div className="absolute inset-0 flex items-center justify-center text-xs text-muted-foreground">
          No artifacts in current results
        </div>
      )}
      {!loading && totalArtifacts > 0 && shownArtifacts === 0 && !dots.some((d) => d.pending) && (
        <div className="absolute inset-0 flex items-center justify-center text-xs text-muted-foreground">
          {totalArtifacts} artifacts seen on &gt;{maxHostCount} hosts — raise the slider to see them
        </div>
      )}
      {/* NAN-1700: dots are already plotted at their event times; this just
          signals the rarity Y/color is still resolving in the background. */}
      {dots.some((d) => d.pending) && (
        <div className="absolute top-2 right-3 flex items-center gap-1.5 text-[10px] text-muted-foreground/80 pointer-events-none">
          <span className="w-1.5 h-1.5 rounded-full bg-muted-foreground/60 animate-pulse" />
          scoring rarity…
        </div>
      )}

      {/* Tooltip card — clamped horizontally so the right edge can't fall off the plot.
          TIP_W is an estimate of the rendered tooltip width; slight over-estimate is safe
          because the inner text truncates at 220px. */}
      {tip && (() => {
        const TIP_W = 260;
        const MARGIN = 8;
        const half = TIP_W / 2;
        const clampedLeft = Math.min(Math.max(tip.px, half + MARGIN), Math.max(half + MARGIN, W - half - MARGIN));
        return (
        <div
          className="pointer-events-none absolute z-10 w-max max-w-[260px] rounded-md border border-primary/35 bg-popover py-2 px-2.5 font-mono shadow-[0_10px_30px_rgba(0,0,0,0.6)]"
          style={{
            left: clampedLeft,
            top: tip.py,
            transform: 'translate(-50%, calc(-100% - 10px))',
          }}
        >
          <div
            className={cn(
              'mb-1 flex items-center gap-1.5 text-[11px] font-semibold',
              tip.d.isRare ? 'text-primary' : 'text-foreground'
            )}
          >
            {tip.d.artifactType === 'hash' ? (
              <Hash className="w-3 h-3 shrink-0" />
            ) : (
              <Globe className="w-3 h-3 shrink-0" />
            )}
            <span className="truncate max-w-[220px]">{tip.d.artifact}</span>
          </div>
          {/* Rarity verdict — the headline. Rarity is measured by how many
              distinct ASSETS (hosts) the artifact is on, not by age. */}
          <div className={cn('text-[10.5px] font-semibold', tip.d.isRare ? 'text-primary' : 'text-muted-foreground')}>
            {tip.d.isRare
              ? `RARE · on ${tip.d.hostCount.toLocaleString()} host${tip.d.hostCount === 1 ? '' : 's'}`
              : tip.d.hostCount >= 9999
              ? 'common · 1000+ hosts'
              : tip.d.hostCount >= COMMON_HOST_THRESHOLD
              ? `common · on ${tip.d.hostCount.toLocaleString()} hosts`
              : tip.d.hostCount === 0
              ? 'not baselined yet'
              : `uncommon · on ${tip.d.hostCount.toLocaleString()} hosts`}
            {/* Novelty only when we have a REAL env-first-seen (NAN-1699) — never
                inferred from the event time, and not for common/unbaselined. */}
            {tip.d.hostCount > 0 &&
              tip.d.hostCount < COMMON_HOST_THRESHOLD &&
              tip.d.envFirstSeen != null &&
              nowMs - tip.d.envFirstSeen.getTime() < NOVEL_WINDOW_MS && (
                <span className="ml-1.5 text-primary font-medium">· new to env</span>
              )}
          </div>
          <div className="text-[10px] text-muted-foreground/90">
            fired{' '}
            <b className="text-foreground font-medium">{tip.d.events.toLocaleString()}</b>
            {tip.d.events === 1 ? ' time' : ' times'} in this window
          </div>
          <div className="mt-1.5 pt-1.5 border-t border-border text-[10px] text-muted-foreground">
            event time{' '}
            <b className="text-foreground font-medium">{fmtUtc(tip.d.firstSeen)}</b>
            {tip.d.envFirstSeen && tip.d.envFirstSeen.getTime() !== tip.d.firstSeen.getTime() && (
              <>
                {' '}·{' '}first in env{' '}
                <b className="text-foreground font-medium">{fmtUtc(tip.d.envFirstSeen)}</b>
              </>
            )}
          </div>
        </div>
        );
      })()}
    </div>
  );
}
