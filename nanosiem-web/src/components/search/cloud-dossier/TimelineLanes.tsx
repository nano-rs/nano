// SPDX-License-Identifier: AGPL-3.0-or-later

import { useMemo } from 'react';
import type { CloudDossierTimeline, TimeRange } from '@/lib/api/types';
import { CloudCard } from '../cloud-overview/shared';

interface TimelineLanesProps {
  timeline: CloudDossierTimeline;
  /** Search time range — used to stamp the ruler above the lanes in UTC */
  timeRange?: TimeRange;
}

const LANE_H = 22;

export function TimelineLanes({ timeline, timeRange }: TimelineLanesProps) {
  const { buckets, lanes, points, label } = timeline;

  const byLane = useMemo(() => {
    const m: Record<string, number[]> = {};
    lanes.forEach((l) => {
      m[l.id] = new Array(buckets).fill(0);
    });
    for (const [b, laneId, w] of points) {
      if (m[laneId] && b >= 0 && b < buckets) {
        m[laneId][b] = Math.max(m[laneId][b], w);
      }
    }
    return m;
  }, [lanes, buckets, points]);

  // Ruler ticks across the bucket grid — 8 evenly-spaced HH:MM labels in UTC
  // derived from the search window. Falls back to "bucket N" when the time
  // range isn't provided (defensive; the dossier always passes one).
  const rulerTicks = useMemo(() => {
    const every = Math.max(1, Math.floor(buckets / 7));
    const tickBuckets: number[] = [];
    for (let i = 0; i < buckets; i += every) tickBuckets.push(i);
    if (tickBuckets[tickBuckets.length - 1] !== buckets - 1) {
      tickBuckets.push(buckets - 1);
    }
    return tickBuckets.map((b) => {
      if (!timeRange) return { b, label: `${b}` };
      const startMs = new Date(timeRange.start).getTime();
      const endMs = new Date(timeRange.end).getTime();
      if (Number.isNaN(startMs) || Number.isNaN(endMs)) return { b, label: `${b}` };
      const bucketMs = (endMs - startMs) / Math.max(1, buckets);
      const atMs = startMs + b * bucketMs;
      const d = new Date(atMs);
      const hh = String(d.getUTCHours()).padStart(2, '0');
      const mm = String(d.getUTCMinutes()).padStart(2, '0');
      return { b, label: `${hh}:${mm}` };
    });
  }, [buckets, timeRange]);

  return (
    <CloudCard
      title="Timeline · service lanes"
      subtitle={label}
      accent="oklch(68% 0.14 60)"
    >
      <div className="p-3 pt-2">
        {lanes.length === 0 ? (
          <div className="py-6 text-center text-[11px] text-muted-foreground/60 font-mono">
            No service activity in this window
          </div>
        ) : (
          <div className="space-y-[4px]">
            {/* Time ruler — HH:MM UTC across the bucket grid */}
            <div className="flex items-center gap-2 mb-1">
              <div className="w-[108px] shrink-0" />
              <div className="flex-1 relative h-3 font-mono text-[9.5px] text-muted-foreground/70">
                {rulerTicks.map(({ b, label: tickLabel }) => (
                  <span
                    key={b}
                    className="absolute tabular-nums whitespace-nowrap"
                    style={{
                      left: `${(b / Math.max(1, buckets - 1)) * 100}%`,
                      transform: 'translateX(-50%)',
                    }}
                  >
                    {tickLabel}
                  </span>
                ))}
              </div>
            </div>
            {lanes.map((lane) => (
              <div key={lane.id} className="flex items-center gap-2">
                <div className="w-[108px] shrink-0 flex items-center gap-1.5 font-mono text-[11px] text-muted-foreground/90">
                  <span
                    className="w-1.5 h-3.5 rounded-sm shrink-0"
                    style={{ background: lane.accent }}
                  />
                  <span className="truncate">{lane.label}</span>
                </div>
                <div
                  className="flex-1 grid relative"
                  style={{
                    gridTemplateColumns: `repeat(${buckets}, minmax(0,1fr))`,
                    height: LANE_H,
                  }}
                >
                  {(byLane[lane.id] ?? []).map((v, b) => (
                    <div key={b} className="flex items-end justify-center">
                      {v > 0 && (
                        <div
                          className="w-full rounded-sm"
                          style={{
                            height: `${Math.min(LANE_H, 5 + v * 5)}px`,
                            background: lane.accent,
                            opacity: 0.2 + v * 0.25,
                          }}
                        />
                      )}
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </CloudCard>
  );
}
