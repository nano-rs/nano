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
