// SPDX-License-Identifier: AGPL-3.0-or-later
import type { TimeRange } from '@/lib/api/types';
import { toApiTimeRange, type TimeRangeValue } from '@/lib/time-range';

/**
 * NAN-3299: the absolute bounds one search run resolved its time range to.
 *
 * A relative pick ("Last hour") resolves against `now` every time it is read.
 * The run resolves it ONCE; every request of that run (rows, timeline, field
 * stats, later pages) and the URL it writes reuse those bounds, so writing
 * them to the URL is not a new search identity and a page flip stays on the
 * page-1 window.
 */
export interface SearchRunScope {
  /** The picker value the run was started with. */
  timeRange: TimeRangeValue;
  /** The bounds it resolved to. */
  range: TimeRange;
}

export function sameTimeRangeValue(a: TimeRangeValue, b: TimeRangeValue): boolean {
  return a === b || JSON.stringify(a) === JSON.stringify(b);
}

/** Bounds for `range`: the run's own when it is the range that run started with. */
export function resolveRunTimeRange(scope: SearchRunScope | null, range: TimeRangeValue): TimeRange {
  return scope && sameTimeRangeValue(scope.timeRange, range) ? scope.range : toApiTimeRange(range);
}

/** The resolved bounds as a fixed range (what the URL carries). */
export function fixedTimeRange(range: TimeRange): TimeRangeValue {
  return { type: 'custom', start: new Date(range.start), end: new Date(range.end) };
}

/**
 * NAN-3884: what a run writes to the URL. A relative pick stays relative
 * (`time=Last 7 days`), so reload, back-nav and copied links re-resolve it
 * and the picker keeps showing the relative label; a fixed range carries the
 * bounds the run resolved.
 */
export function urlTimeRange(value: TimeRangeValue, range: TimeRange): TimeRangeValue {
  if (value.type === 'preset' && value.preset) return { type: 'preset', preset: value.preset };
  return fixedTimeRange(range);
}

/**
 * NAN-3883: how long after a run starts an identical request is treated as a
 * repeat of it, not a new search.
 */
export const DUPLICATE_RUN_WINDOW_MS = 1_500;

/** NAN-3883: what makes two user runs the same search. */
export interface SearchRunStart {
  key: string;
  startMs: number;
  endMs: number;
  at: number;
}

/**
 * NAN-3883: the identity of a run started at `at`. The window is compared as
 * resolved bounds, so a relative pick and the absolute URL it was written to
 * moments ago (or a re-resolve of the same preset) are the same search.
 */
export function searchRunStart(
  query: string, mode: string, dataset: string, prevalenceMax: number, range: TimeRangeValue, at: number,
): SearchRunStart {
  const resolved = toApiTimeRange(range);
  return {
    key: [mode, query.trim(), dataset, String(prevalenceMax)].join('\u0000'),
    startMs: Date.parse(resolved.start),
    endMs: Date.parse(resolved.end),
    at,
  };
}

/** NAN-3883: `next` repeats `previous` (same search, moments later). */
export function repeatsRun(previous: SearchRunStart | null, next: SearchRunStart): boolean {
  if (!previous || previous.key !== next.key) return false;
  const elapsed = next.at - previous.at;
  return elapsed >= 0 && elapsed < DUPLICATE_RUN_WINDOW_MS
    && Math.abs(previous.startMs - next.startMs) <= DUPLICATE_RUN_WINDOW_MS
    && Math.abs(previous.endMs - next.endMs) <= DUPLICATE_RUN_WINDOW_MS;
}
