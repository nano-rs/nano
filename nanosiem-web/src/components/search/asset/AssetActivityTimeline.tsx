// SPDX-License-Identifier: AGPL-3.0-or-later

import type { AssetDossierTimeline } from '@/lib/api/types';
import { cn } from '@/lib/utils';

interface AssetActivityTimelineProps {
  timeline: AssetDossierTimeline;
  /** Label for the time span covered, e.g. "last 7 days" or "last 24h". */
  spanLabel: string;
  /** Optional markers — rendered as pills above the grid (unused until we derive them). */
  markers?: { label: string; severity: 'critical' | 'warn' }[];
}

const LANE_LABELS: Record<string, string> = {
  auth: 'AUTH',
  proc: 'PROC',
  net: 'NET',
  file: 'FILE',
  alert: 'ALERT',
};

export function AssetActivityTimeline({
  timeline,
  spanLabel,
  markers = [],
}: AssetActivityTimelineProps) {
  const { buckets, lanes, points } = timeline;
  // Build lane × bucket → weight lookup
  const grid: number[][] = lanes.map(() => new Array(buckets).fill(0));
  for (const [bucket, lane, weight] of points) {
    if (lane < grid.length && bucket < grid[lane].length) {
      grid[lane][bucket] = Math.max(grid[lane][bucket], weight);
    }
  }

  // Highlight the latest bucket as "now" when the alert lane has a high weight there
  const alertLaneIdx = lanes.indexOf('alert');
  const lastBucket = buckets - 1;
  const hasLateIncident =
    alertLaneIdx >= 0 &&
    grid[alertLaneIdx]?.[lastBucket] !== undefined &&
    grid[alertLaneIdx][lastBucket] >= 2;

  return (
    <div className="bg-card border border-border rounded-lg p-3">
      <div className="flex items-center justify-between mb-2 gap-3 flex-wrap">
        <div className="flex items-center gap-3">
          <div className="text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground/70">
            Activity · {spanLabel}
          </div>
          {markers.map((m, i) => (
            <span
              key={i}
              className={cn(
                'inline-flex items-center gap-1 text-[10px] font-mono px-1.5 py-0.5 rounded',
                m.severity === 'critical'
                  ? 'bg-[oklch(62%_0.18_28/0.12)] text-[oklch(62%_0.18_28)]'
                  : 'bg-[oklch(72%_0.14_80/0.12)] text-[oklch(72%_0.14_80)]'
              )}
            >
              {m.label}
            </span>
          ))}
        </div>
        <div className="text-[10.5px] text-muted-foreground/70 font-mono">
          hover cells to drill in
        </div>
      </div>

      <div className="flex">
        <div className="shrink-0 w-[56px] flex flex-col gap-[3px] pt-0.5">
          {lanes.map((l) => (
            <div
              key={l}
              className="h-[14px] text-[10px] font-mono uppercase tracking-[0.08em] text-muted-foreground/70 flex items-center"
            >
              {LANE_LABELS[l] ?? l.toUpperCase()}
            </div>
          ))}
        </div>
        <div className="flex-1 flex flex-col gap-[3px]">
          {grid.map((row, laneIdx) => (
            <div
              key={laneIdx}
              className="grid gap-[2px]"
              style={{ gridTemplateColumns: `repeat(${buckets}, minmax(0, 1fr))` }}
            >
              {row.map((w, b) => {
                const isIncident =
                  hasLateIncident && b === lastBucket && laneIdx === alertLaneIdx;
                const bg = isIncident
                  ? 'oklch(62% 0.18 28)'
                  : w === 0
                  ? 'var(--border)'
                  : w === 1
                  ? 'oklch(72% 0.10 240)'
                  : w === 2
                  ? 'oklch(72% 0.14 240)'
                  : 'oklch(75% 0.18 240)';
                return (
                  <div
                    key={b}
                    className="h-[14px] rounded-[2px] transition-colors cursor-pointer hover:outline hover:outline-1 hover:outline-primary"
                    style={{ background: bg, opacity: w === 0 ? 0.4 : 0.9 }}
                    title={`${LANE_LABELS[lanes[laneIdx]] ?? lanes[laneIdx]} · bucket ${b} · intensity ${w}`}
                  />
                );
              })}
            </div>
          ))}
        </div>
      </div>

      <div className="flex justify-between mt-1.5 pl-[56px] text-[9.5px] font-mono text-muted-foreground/60 tabular-nums">
        <span>oldest</span>
        <span>now</span>
      </div>
    </div>
  );
}
