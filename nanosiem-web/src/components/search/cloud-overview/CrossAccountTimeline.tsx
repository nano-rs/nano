// SPDX-License-Identifier: AGPL-3.0-or-later

import { useMemo } from 'react';
import { cn } from '@/lib/utils';
import type { CloudOverviewTimeline } from '@/lib/api/types';
import { CloudCard, cloudSevTone } from './shared';

interface CrossAccountTimelineProps {
  timeline: CloudOverviewTimeline;
}

function bucketLabel(bucketIdx: number, totalBuckets: number): string {
  // 48 buckets across 24h → each bucket is 30min. Convert to HH:MM.
  const minutesPerBucket = (24 * 60) / totalBuckets;
  const minuteOffset = bucketIdx * minutesPerBucket;
  const hh = Math.floor(minuteOffset / 60);
  const mm = Math.floor(minuteOffset % 60);
  return `${String(hh).padStart(2, '0')}:${String(mm).padStart(2, '0')}`;
}

export function CrossAccountTimeline({ timeline }: CrossAccountTimelineProps) {
  const { lanes, buckets, points, markers, label } = timeline;

  const byLaneBucket = useMemo(() => {
    const m: Record<string, number[]> = {};
    lanes.forEach((l) => {
      m[l.id] = new Array(buckets).fill(0);
    });
    points.forEach(([b, laneId, v]) => {
      if (m[laneId] && b >= 0 && b < buckets) m[laneId][b] = v;
    });
    return m;
  }, [lanes, buckets, points]);

  const maxV = useMemo(() => {
    let max = 0;
    for (const arr of Object.values(byLaneBucket)) {
      for (const v of arr) if (v > max) max = v;
    }
    return Math.max(1, max);
  }, [byLaneBucket]);

  const rulerTicks = useMemo(() => {
    // 8 evenly spaced ticks + the last one, matching the mockup spacing
    const every = Math.max(1, Math.floor(buckets / 8));
    const ticks: number[] = [];
    for (let i = 0; i < buckets; i += every) ticks.push(i);
    if (ticks[ticks.length - 1] !== buckets - 1) ticks.push(buckets - 1);
    return ticks;
  }, [buckets]);

  return (
    <CloudCard title="Cross-account timeline" subtitle={label} accent="oklch(68% 0.14 240)">
      <div className="p-3">
        <div className="grid grid-cols-[100px_1fr] gap-2">
          <div />
          <div className="relative h-4 font-mono text-[9.5px] text-muted-foreground/70">
            {rulerTicks.map((b) => (
              <span
                key={b}
                className="absolute tabular-nums"
                style={{
                  left: `${(b / Math.max(1, buckets - 1)) * 100}%`,
                  transform: 'translateX(-50%)',
                }}
              >
                {bucketLabel(b, buckets)}
              </span>
            ))}
          </div>

          {lanes.map((lane, laneIdx) => (
            <div key={lane.id} className="contents">
              <div className="flex items-center gap-1.5 font-mono text-[11px] text-muted-foreground/80">
                <span className="w-1 h-3 rounded-sm" style={{ background: lane.accent }} />
                <span className="truncate">{lane.label}</span>
              </div>
              <div className="relative h-7 bg-foreground/[0.03] rounded-sm overflow-hidden">
                <div
                  className="absolute inset-0 grid"
                  style={{ gridTemplateColumns: `repeat(${buckets}, 1fr)` }}
                >
                  {byLaneBucket[lane.id].map((v, i) => {
                    const h = (v / maxV) * 100;
                    return (
                      <div key={i} className="relative flex items-end">
                        <div
                          className="w-full"
                          style={{
                            height: `${Math.max(4, h)}%`,
                            background: lane.accent,
                            opacity: 0.9,
                          }}
                        />
                      </div>
                    );
                  })}
                </div>
                {laneIdx === 0 &&
                  markers.map((m) => {
                    const tone = cloudSevTone(m.severity);
                    return (
                      <div
                        key={m.at}
                        className={cn('absolute top-0 bottom-0 w-px', tone.bg)}
                        style={{
                          left: `${(m.at / Math.max(1, buckets - 1)) * 100}%`,
                        }}
                      >
                        <span
                          className={cn(
                            'absolute -top-0.5 -translate-x-1/2 text-[8.5px] font-mono px-1 rounded-sm',
                            tone.bg,
                            tone.text
                          )}
                        >
                          ▼
                        </span>
                      </div>
                    );
                  })}
              </div>
            </div>
          ))}
        </div>

        {markers.length > 0 && (
          <div className="mt-2 pt-2 border-t border-border flex flex-wrap gap-3 text-[10.5px] font-mono">
            {markers.map((m) => {
              const tone = cloudSevTone(m.severity);
              return (
                <div key={m.at} className="flex items-center gap-1.5">
                  <span className={cn('w-1.5 h-1.5 rounded-full', tone.dot)} />
                  <span className="text-muted-foreground/80 tabular-nums">
                    {bucketLabel(m.at, buckets)}
                  </span>
                  <span className={tone.text}>{m.label}</span>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </CloudCard>
  );
}
