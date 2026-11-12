// SPDX-License-Identifier: AGPL-3.0-or-later
import { formatInTimeZone } from 'date-fns-tz';

/**
 * Event Stream timeline x-axis: tick placement and labels (NAN-5320).
 *
 * The ticks used to top out at a 24h step, so a multi-year window produced
 * thousands of daily ticks that recharts thinned by pixel gap, and the
 * yearless `M/d HH:mm` labels then repeated (`5/11, 1/11, 9/7, …`). Long
 * windows now step by calendar months/years, and labels carry the year
 * whenever the window crosses one.
 */

const SECOND = 1000;
const MINUTE = 60 * SECOND;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

const FIXED_INTERVALS = [
  SECOND, 2 * SECOND, 5 * SECOND, 10 * SECOND, 15 * SECOND, 30 * SECOND,
  MINUTE, 5 * MINUTE, 10 * MINUTE, 15 * MINUTE, 30 * MINUTE,
  HOUR, 2 * HOUR, 4 * HOUR, 6 * HOUR, 12 * HOUR,
  DAY, 2 * DAY, 7 * DAY, 14 * DAY,
];

/** Calendar steps (in months) for windows too long for a fixed step. */
const MONTH_STEPS = [1, 2, 3, 6, 12, 24, 60, 120];
/** Average month length, only for choosing a step size. */
const AVG_MONTH = 30.44 * DAY;

const TARGET_TICKS = 20;

/** Evenly spaced tick timestamps across `[start, end]` (UTC). */
export function timelineAxisTicks(start: number, end: number, target: number = TARGET_TICKS): number[] {
  if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start) return [];
  const raw = (end - start) / target;

  const fixed = FIXED_INTERVALS.find((i) => i >= raw);
  if (fixed !== undefined) {
    const ticks: number[] = [];
    for (let t = Math.ceil(start / fixed) * fixed; t <= end; t += fixed) ticks.push(t);
    return ticks;
  }

  // Calendar-aligned: first of a month whose index is a multiple of the step.
  const step = MONTH_STEPS.find((m) => m * AVG_MONTH >= raw) ?? MONTH_STEPS[MONTH_STEPS.length - 1];
  const s = new Date(start);
  let monthIndex = s.getUTCFullYear() * 12 + s.getUTCMonth();
  if (Date.UTC(Math.floor(monthIndex / 12), monthIndex % 12, 1) < start) monthIndex += 1;
  monthIndex = Math.ceil(monthIndex / step) * step;
  const ticks: number[] = [];
  for (;;) {
    const t = Date.UTC(Math.floor(monthIndex / 12), monthIndex % 12, 1);
    if (t > end) break;
    ticks.push(t);
    monthIndex += step;
  }
  return ticks;
}

/** Whether `[start, end]` crosses a UTC calendar year. */
export function spansYears(start: number, end: number): boolean {
  return new Date(start).getUTCFullYear() !== new Date(end).getUTCFullYear();
}

/** Axis tick label for `timestamp`, given the window it sits in (UTC). */
export function formatTimelineAxisLabel(timestamp: number, start: number, end: number): string {
  const date = new Date(timestamp);
  const range = end - start;
  if (range < 2 * MINUTE) return formatInTimeZone(date, 'UTC', 'HH:mm:ss.SSS');
  if (range < 30 * MINUTE) return formatInTimeZone(date, 'UTC', 'HH:mm:ss');
  if (range <= DAY) return formatInTimeZone(date, 'UTC', 'HH:mm');
  // Month-stepped ticks sit on the 1st at midnight: the month is the label.
  if (range / TARGET_TICKS > 14 * DAY) return formatInTimeZone(date, 'UTC', 'MMM yyyy');
  if (spansYears(start, end)) return formatInTimeZone(date, 'UTC', 'M/d/yy HH:mm');
  return formatInTimeZone(date, 'UTC', 'M/d HH:mm');
}

/** Tooltip time for a bucket, given the window it sits in (UTC). */
export function formatTimelineTooltipTime(timestamp: number, start: number, end: number): string {
  const date = new Date(timestamp);
  const range = end - start;
  if (range < 2 * MINUTE) return formatInTimeZone(date, 'UTC', 'HH:mm:ss.SSS');
  if (range < 30 * MINUTE) return formatInTimeZone(date, 'UTC', 'HH:mm:ss');
  if (range <= DAY) return formatInTimeZone(date, 'UTC', 'HH:mm:ss');
  if (spansYears(start, end)) return formatInTimeZone(date, 'UTC', 'MMM d yyyy, HH:mm');
  return formatInTimeZone(date, 'UTC', 'MMM d, HH:mm');
}
