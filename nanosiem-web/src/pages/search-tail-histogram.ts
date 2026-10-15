// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Live tail keeps the EVENT STREAM histogram moving (NAN-3254).
 *
 * Tail ticks skip the histogram companion (`skip_histogram: true`), so the
 * chart used to stay frozen at the moment the search ran. Re-fetching it on
 * every tick would cost a whole-window aggregate per tick. Each batch of fresh
 * tail rows is already in hand, so the page counts them into the server's
 * buckets instead:
 *
 * - a row increments the bucket whose start contains its timestamp;
 * - when "now" crosses a bucket boundary, zero buckets are appended so the
 *   newest bucket exists before anything lands in it;
 * - buckets that have slid fully out of the window (`windowStartMs`) are
 *   dropped, so the chart rolls with the clock the way the result list does.
 *
 * Only rows newer than `countAfterMs` are counted. Events at or before it were
 * already in the histogram the search returned, and the tail's lookback
 * overlap would otherwise re-deliver (and double count) them.
 *
 * The bucket width is inferred from the histogram's own spacing (the server
 * zero-fills, so consecutive buckets are evenly spaced). With fewer than two
 * buckets the width is unknown and the histogram is returned unchanged.
 */

import { parseUTCTimestamp } from '@/lib/date-utils';

export interface HistogramBucket {
  time: string;
  count: number;
}

export interface AdvanceTailHistogramOptions {
  /** Wall clock (epoch ms). Buckets are appended up to the one holding it. */
  nowMs: number;
  /** Rows at or before this time are already counted in the histogram. */
  countAfterMs: number;
  /** Buckets ending at or before this (epoch ms) are dropped. Omit to keep all. */
  windowStartMs?: number;
}

/** The server counted the complete query window, regardless of page contents. */
export function tailHistogramCutoff(previousMs: number, queryEndMs: number): number {
  return Number.isFinite(queryEndMs) ? Math.max(previousMs, queryEndMs) : previousMs;
}

/** Upper bound on buckets appended in one call (a long-asleep tab must not loop for ages). */
const MAX_APPENDED_BUCKETS = 10_000;

/** Median spacing between consecutive bucket starts, or null with fewer than two buckets. */
export function histogramBucketMs(starts: number[]): number | null {
  if (starts.length < 2) return null;
  const gaps: number[] = [];
  for (let i = 1; i < starts.length; i++) {
    const gap = starts[i] - starts[i - 1];
    if (gap > 0) gaps.push(gap);
  }
  if (gaps.length === 0) return null;
  gaps.sort((a, b) => a - b);
  return gaps[Math.floor(gaps.length / 2)];
}

/**
 * Fold one batch of tail arrivals (and the passage of time) into the
 * histogram. Pure: returns the input array itself when nothing changed, so a
 * quiet tick does not re-render the chart.
 */
export function advanceTailHistogram(
  histogram: HistogramBucket[],
  arrivalTimesMs: number[],
  { nowMs, countAfterMs, windowStartMs }: AdvanceTailHistogramOptions,
): HistogramBucket[] {
  if (histogram.length < 2) return histogram;
  const buckets = histogram
    .map((b) => ({ time: b.time, count: b.count, start: parseUTCTimestamp(b.time).getTime() }))
    .filter((b) => Number.isFinite(b.start))
    .sort((a, b) => a.start - b.start);
  const bucketMs = histogramBucketMs(buckets.map((b) => b.start));
  if (bucketMs === null) return histogram;

  let changed = false;

  // Append empty buckets until the newest one holds `nowMs`.
  let lastStart = buckets[buckets.length - 1].start;
  for (let n = 0; lastStart + bucketMs <= nowMs && n < MAX_APPENDED_BUCKETS; n++) {
    lastStart += bucketMs;
    buckets.push({ time: new Date(lastStart).toISOString(), count: 0, start: lastStart });
    changed = true;
  }

  // Count the arrivals. Bucket boundaries are aligned to the first bucket.
  // A bucket missing from the server's series is not invented here.
  const firstStart = buckets[0].start;
  const byStart = new Map(buckets.map((b) => [b.start, b]));
  for (const ts of arrivalTimesMs) {
    if (!Number.isFinite(ts) || ts <= countAfterMs || ts < firstStart || ts > nowMs) continue;
    const bucket = byStart.get(firstStart + Math.floor((ts - firstStart) / bucketMs) * bucketMs);
    if (!bucket) continue;
    bucket.count += 1;
    changed = true;
  }

  // Slide: drop buckets that ended before the window starts.
  let firstKept = 0;
  if (windowStartMs !== undefined) {
    while (firstKept < buckets.length - 1 && buckets[firstKept].start + bucketMs <= windowStartMs) firstKept++;
    if (firstKept > 0) changed = true;
  }

  if (!changed) return histogram;
  return buckets.slice(firstKept).map(({ time, count }) => ({ time, count }));
}

/**
 * Re-anchoring the live count on the server (NAN-3263).
 *
 * Counting tail rows into the histogram (above) keeps the chart moving between
 * server reads, but it cannot be the count's source of truth:
 *
 * - The row feed is not complete. The lake makes events searchable up to
 *   ~2 min late and per shard, and both the poll (one capped page per tick)
 *   and the follow stream (a short re-read behind its newest event) can miss
 *   a late part whose events sort below the page they read. Every missed
 *   event was a permanent hole, so after one window the whole chart was built
 *   from an undercounted feed (live: 17–23% low on a 920/min source).
 * - Roll-off is per bucket. A lean 1h histogram is served from 5-minute
 *   rollups, so the oldest bucket's full count stayed until all of it left
 *   the window and then dropped at once: a 5-minute saw-tooth.
 *
 * So the tail periodically re-reads the histogram for the true rolling window
 * `[now - span, now]` (one aggregate, served from the count rollups where it
 * can be) and replaces the local one. Its first bucket is partial exactly
 * where the window starts, so roll-off is exact at every anchor, and the
 * server sees every event the lake has made visible. Between anchors the
 * arrival counting above carries the chart, and the error is bounded by one
 * re-anchor interval of arrivals.
 */

/** Never re-anchor more often than this. */
export const TAIL_REANCHOR_MIN_MS = 60_000;
/** Never let the count drift on local counting for longer than this. */
export const TAIL_REANCHOR_MAX_MS = 15 * 60_000;
/** Upper bound on remembered arrival times awaiting the next anchor. */
export const TAIL_ARRIVAL_LOG_MAX = 50_000;

/**
 * How often to re-read the window's histogram. One sixtieth of the span keeps
 * the drift under ~2% of the window, clamped to [1 min, 15 min] and never more
 * often than the tail ticks.
 */
export function tailReanchorIntervalMs(spanMs: number, tailIntervalMs: number): number {
  const proportional = Number.isFinite(spanMs) && spanMs > 0 ? Math.round(spanMs / 60) : 0;
  return Math.min(TAIL_REANCHOR_MAX_MS, Math.max(TAIL_REANCHOR_MIN_MS, tailIntervalMs, proportional));
}

/** Whether a tick should re-anchor. `lastRequestedMs` 0 = never anchored since arming. */
export function tailReanchorDue(
  lastRequestedMs: number,
  nowMs: number,
  spanMs: number,
  tailIntervalMs: number,
): boolean {
  if (!(Number.isFinite(spanMs) && spanMs > 0)) return false;
  return lastRequestedMs <= 0 || nowMs - lastRequestedMs >= tailReanchorIntervalMs(spanMs, tailIntervalMs);
}

/**
 * Remember arrival times the next anchor may need to re-apply. Only times
 * after `countAfterMs` can matter (older ones are the server's to count).
 * Mutates and bounds `log`, keeping the newest.
 */
export function logTailArrivals(log: number[], arrivalTimesMs: number[], countAfterMs: number): void {
  for (const ts of arrivalTimesMs) {
    if (Number.isFinite(ts) && ts > countAfterMs) log.push(ts);
  }
  if (log.length > TAIL_ARRIVAL_LOG_MAX) log.splice(0, log.length - TAIL_ARRIVAL_LOG_MAX);
}

export interface ReanchorTailHistogramOptions {
  /** The `end` the anchor asked the server for (epoch ms). */
  anchorEndMs: number;
  /** Wall clock when the anchor landed (epoch ms). */
  nowMs: number;
  /** `nowMs - span`: buckets ending at or before this are dropped. */
  windowStartMs?: number;
}

export interface ReanchoredTailHistogram {
  histogram: HistogramBucket[];
  /** The arrival log after the anchor: only arrivals the server could not have counted. */
  arrivalLog: number[];
}

/**
 * Replace the local histogram with the server's read of the rolling window.
 *
 * The server counted everything at or before `anchorEndMs` that the lake had
 * made visible; arrivals after it (the tail kept folding while the anchor was
 * in flight) are re-applied on top. Arrivals at or before it are forgotten: a
 * late one the server missed is counted by the next anchor, never twice.
 */
export function reanchorTailHistogram(
  serverHistogram: HistogramBucket[],
  arrivalLog: number[],
  { anchorEndMs, nowMs, windowStartMs }: ReanchorTailHistogramOptions,
): ReanchoredTailHistogram {
  const pending = arrivalLog.filter((ts) => ts > anchorEndMs);
  const histogram = advanceTailHistogram(serverHistogram, pending, {
    nowMs,
    countAfterMs: anchorEndMs,
    windowStartMs,
  });
  return { histogram, arrivalLog: pending };
}

export interface TailReanchorTrustOptions {
  /** The window the anchor asked the server for (epoch ms). */
  anchorStartMs: number;
  anchorEndMs: number;
}

/**
 * Whether a resolved re-anchor may replace the live timeline (NAN-3267).
 *
 * The live count is the timeline's sum, so a re-anchor that installs an
 * empty or all-zero series renders "0 events" until the next one lands
 * (live: one 20 s sample read 0 between 80,582 and 82,259). The page keeps
 * the last known timeline unless the read carries real data:
 *
 * - an empty series, or one with no parseable bucket, is not data (a failed
 *   or shed companion answers `histogram: []`);
 * - a non-zero series is the server's count of the window and always wins;
 * - an all-zero series is accepted only when nothing on screen contradicts
 *   it. Events counted in a bucket that lies entirely inside the anchored
 *   window exist (the lake never un-publishes them), so a zero read over
 *   them is a zero-filled miss, not a quiet source. A source that really
 *   went quiet for the whole window has no such buckets and reads 0.
 */
export function tailReanchorTrusted(
  serverHistogram: HistogramBucket[] | null | undefined,
  currentHistogram: HistogramBucket[],
  { anchorStartMs, anchorEndMs }: TailReanchorTrustOptions,
): boolean {
  if (!Array.isArray(serverHistogram) || serverHistogram.length === 0) return false;
  let total = 0;
  let parseable = 0;
  for (const bucket of serverHistogram) {
    if (!Number.isFinite(parseUTCTimestamp(bucket.time).getTime())) continue;
    parseable += 1;
    if (Number.isFinite(bucket.count) && bucket.count > 0) total += bucket.count;
  }
  if (parseable === 0) return false;
  if (total > 0) return true;

  const current = currentHistogram
    .map((b) => ({ count: b.count, start: parseUTCTimestamp(b.time).getTime() }))
    .filter((b) => Number.isFinite(b.start))
    .sort((a, b) => a.start - b.start);
  const bucketMs = histogramBucketMs(current.map((b) => b.start)) ?? 0;
  return !current.some(
    (b) => b.count > 0 && b.start >= anchorStartMs && b.start + bucketMs <= anchorEndMs,
  );
}

/** `5_400_000` → `1h 30m`, `3_600_000` → `1h`. At most two whole units, largest first. */
export function formatTailSpan(spanMs: number): string {
  let seconds = Math.max(0, Math.round(spanMs / 1000));
  const units: Array<[string, number]> = [['d', 86_400], ['h', 3_600], ['m', 60], ['s', 1]];
  const parts: string[] = [];
  for (const [unit, size] of units) {
    if (seconds >= size) {
      parts.push(`${Math.floor(seconds / size)}${unit}`);
      seconds %= size;
    }
    if (parts.length === 2) break;
  }
  return parts.length > 0 ? parts.join(' ') : '0s';
}

/** The time-range label while the tail rolls the window: `Last 1h · live`. */
export function tailRollingRangeLabel(spanMs: number): string {
  return `Last ${formatTailSpan(spanMs)} · live`;
}
