// SPDX-License-Identifier: AGPL-3.0-or-later

/** NAN-2599: hourly buckets for the LogSourceDetail ingest sparkline. */

import type { LogSourceStatsPoint } from '@/lib/api/types';

const HOUR_MS = 3_600_000;

export interface HourBucket {
  hour: number;
  events: number;
  parseFailures: number;
}

/** Pure: `hours` contiguous hourly buckets ending at the current hour, zero-filled. */
export function hourlyBuckets(points: LogSourceStatsPoint[], hours: number, now: number): HourBucket[] {
  const current = Math.floor(now / HOUR_MS) * HOUR_MS;
  const byHour = new Map<number, LogSourceStatsPoint>();
  for (const p of points) {
    const t = Math.floor(new Date(p.hour).getTime() / HOUR_MS) * HOUR_MS;
    if (Number.isNaN(t)) continue;
    const prev = byHour.get(t);
    byHour.set(t, prev ? { ...prev, events: prev.events + p.events, parse_failures: prev.parse_failures + p.parse_failures } : p);
  }
  return Array.from({ length: hours }, (_, i) => {
    const hour = current - (hours - 1 - i) * HOUR_MS;
    const p = byHour.get(hour);
    return { hour, events: p?.events ?? 0, parseFailures: p?.parse_failures ?? 0 };
  });
}

