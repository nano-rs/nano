// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from 'vitest';
import {
  advanceTailHistogram,
  formatTailSpan,
  histogramBucketMs,
  logTailArrivals,
  reanchorTailHistogram,
  tailHistogramCutoff,
  TAIL_ARRIVAL_LOG_MAX,
  tailReanchorDue,
  tailReanchorIntervalMs,
  tailReanchorTrusted,
  tailRollingRangeLabel,
  type HistogramBucket,
} from './search-tail-histogram';

const MIN = 60_000;
const T0 = Date.parse('2026-10-07T12:00:00.000Z');

/** Server-shaped histogram (space-separated UTC, no zone) with 1-minute buckets. */
function serverHistogram(counts: number[]): HistogramBucket[] {
  return counts.map((count, i) => ({
    time: new Date(T0 + i * MIN).toISOString().replace('T', ' ').replace('Z', ''),
    count,
  }));
}

const startsOf = (h: HistogramBucket[]) => h.map((b) => Date.parse(b.time.includes('Z') ? b.time : `${b.time.replace(' ', 'T')}Z`));

describe('histogramBucketMs', () => {
  it('is the median spacing', () => {
    expect(histogramBucketMs([0, 60, 120, 180, 1000])).toBe(60);
  });
  it('is unknown with fewer than two buckets', () => {
    expect(histogramBucketMs([5])).toBeNull();
    expect(histogramBucketMs([])).toBeNull();
  });
});

describe('advanceTailHistogram', () => {
  it('increments the bucket each arrival falls in', () => {
    const h = serverHistogram([3, 4, 5]);
    const next = advanceTailHistogram(h, [T0 + 2 * MIN + 1_000, T0 + 2 * MIN + 59_000, T0 + MIN + 10], {
      nowMs: T0 + 2 * MIN + 59_500,
      countAfterMs: T0,
    });
    expect(next.map((b) => b.count)).toEqual([3, 5, 7]);
    // Server bucket labels are preserved untouched.
    expect(next.map((b) => b.time)).toEqual(h.map((b) => b.time));
  });

  it('does not double count rows the search already counted', () => {
    const h = serverHistogram([3, 4, 5]);
    const cutoff = T0 + 2 * MIN + 30_000;
    const next = advanceTailHistogram(h, [T0 + 2 * MIN + 10_000, cutoff, cutoff + 1], {
      nowMs: T0 + 2 * MIN + 50_000,
      countAfterMs: cutoff,
    });
    expect(next.map((b) => b.count)).toEqual([3, 4, 6]);
  });

  it('appends buckets when now crosses a boundary and counts into them', () => {
    const h = serverHistogram([1, 1, 1]);
    const now = T0 + 4 * MIN + 5_000; // two boundaries past the last bucket (12:02)
    const next = advanceTailHistogram(h, [T0 + 4 * MIN + 1_000], { nowMs: now, countAfterMs: T0 });
    expect(next).toHaveLength(5);
    expect(startsOf(next)).toEqual([0, 1, 2, 3, 4].map((i) => T0 + i * MIN));
    expect(next.map((b) => b.count)).toEqual([1, 1, 1, 0, 1]);
  });

  it('slides the window: buckets that ended before the window start are dropped', () => {
    const h = serverHistogram([9, 8, 7, 6]);
    const now = T0 + 5 * MIN + 1_000;
    const next = advanceTailHistogram(h, [], {
      nowMs: now,
      countAfterMs: T0,
      windowStartMs: now - 4 * MIN, // 12:01:01 → 12:00 bucket ended at 12:01, dropped
    });
    expect(startsOf(next)).toEqual([1, 2, 3, 4, 5].map((i) => T0 + i * MIN));
    expect(next.map((b) => b.count)).toEqual([8, 7, 6, 0, 0]);
  });

  it('ignores future-skewed and pre-histogram timestamps', () => {
    const h = serverHistogram([0, 0]);
    const next = advanceTailHistogram(h, [T0 + 10 * MIN, T0 - 5 * MIN, Number.NaN], {
      nowMs: T0 + MIN + 30_000,
      countAfterMs: 0,
    });
    expect(next).toBe(h);
  });

  it('returns the same array on a quiet tick inside the current bucket', () => {
    const h = serverHistogram([1, 2]);
    expect(advanceTailHistogram(h, [], { nowMs: T0 + MIN + 30_000, countAfterMs: T0, windowStartMs: T0 })).toBe(h);
  });

  it('leaves a histogram with no inferable width alone', () => {
    const h = serverHistogram([4]);
    expect(advanceTailHistogram(h, [T0 + 1_000], { nowMs: T0 + 5 * MIN, countAfterMs: 0 })).toBe(h);
    expect(advanceTailHistogram([], [T0], { nowMs: T0, countAfterMs: 0 })).toEqual([]);
  });

  it('does not mutate its input', () => {
    const h = serverHistogram([1, 1]);
    const copy = h.map((b) => ({ ...b }));
    advanceTailHistogram(h, [T0 + MIN + 1], { nowMs: T0 + 3 * MIN, countAfterMs: 0, windowStartMs: T0 + 2 * MIN });
    expect(h).toEqual(copy);
  });
});

describe('tail re-anchor cadence (NAN-3263)', () => {
  it('is a sixtieth of the span, clamped to [1 min, 15 min] and the tick', () => {
    expect(tailReanchorIntervalMs(60 * MIN, 15_000)).toBe(MIN);
    expect(tailReanchorIntervalMs(15 * MIN, 15_000)).toBe(MIN);
    expect(tailReanchorIntervalMs(4 * 60 * MIN, 15_000)).toBe(4 * MIN);
    expect(tailReanchorIntervalMs(7 * 24 * 60 * MIN, 15_000)).toBe(15 * MIN);
    expect(tailReanchorIntervalMs(60 * MIN, 5 * MIN)).toBe(5 * MIN);
  });

  it('is due on the first tick after arming, then once per interval', () => {
    expect(tailReanchorDue(0, T0, 60 * MIN, 15_000)).toBe(true);
    expect(tailReanchorDue(T0, T0 + 45_000, 60 * MIN, 15_000)).toBe(false);
    expect(tailReanchorDue(T0, T0 + MIN, 60 * MIN, 15_000)).toBe(true);
  });

  it('never runs without a usable span', () => {
    expect(tailReanchorDue(0, T0, 0, 15_000)).toBe(false);
    expect(tailReanchorDue(0, T0, Number.NaN, 15_000)).toBe(false);
  });
});

describe('logTailArrivals', () => {
  it('keeps only arrivals after the cutoff, bounded to the newest', () => {
    const log: number[] = [];
    logTailArrivals(log, [T0 - 1, T0, T0 + 1, Number.NaN, T0 + 2], T0);
    expect(log).toEqual([T0 + 1, T0 + 2]);
    const big = Array.from({ length: TAIL_ARRIVAL_LOG_MAX + 5 }, (_, i) => T0 + 10 + i);
    logTailArrivals(log, big, T0);
    expect(log).toHaveLength(TAIL_ARRIVAL_LOG_MAX);
    expect(log[log.length - 1]).toBe(big[big.length - 1]);
  });
});

describe('reanchorTailHistogram', () => {
  it('takes the server window and re-applies only arrivals the server could not count', () => {
    const server = serverHistogram([2, 3, 4]);
    const anchorEndMs = T0 + 2 * MIN + 20_000;
    // Folded while the anchor was in flight: one before its end (the server
    // has it), two after (it cannot have them).
    const log = [T0 + 2 * MIN + 10_000, anchorEndMs + 1_000, T0 + 3 * MIN + 5_000];
    const next = reanchorTailHistogram(server, log, { anchorEndMs, nowMs: T0 + 3 * MIN + 10_000 });
    expect(next.histogram.map((b) => b.count)).toEqual([2, 3, 5, 1]);
    expect(next.arrivalLog).toEqual([anchorEndMs + 1_000, T0 + 3 * MIN + 5_000]);
  });
});

/**
 * NAN-3263 live shape: a 1h window over 5-minute (rollup) buckets, a steady
 * source, a lake that makes events visible 60 s late, and a tail feed that
 * misses one late event in five. Samples the displayed count (the histogram
 * sum) every 15 s for 70 minutes against the true count of [now - 1h, now].
 */
describe('live count over a rolling window (NAN-3263)', () => {
  const SPAN = 60 * MIN;
  const BUCKET = 5 * MIN;
  const TICK = 15_000;
  const LAG = MIN;
  const EVERY_MS = 2_000; // 30 events / min
  const PER_MIN = MIN / EVERY_MS;
  const START = Date.parse('2026-10-08T02:16:20.000Z');
  const ORIGIN = START - 2 * SPAN;
  const eventsIn = (fromExclusive: number, toInclusive: number) => {
    const out: number[] = [];
    for (let t = Math.ceil((fromExclusive + 1 - ORIGIN) / EVERY_MS) * EVERY_MS + ORIGIN; t <= toInclusive; t += EVERY_MS) out.push(t);
    return out;
  };
  const truth = (nowMs: number) => eventsIn(nowMs - SPAN, nowMs).length;
  /** What the server answers for [end - span, end]: only what the lake has made visible. */
  const serverAt = (endMs: number): HistogramBucket[] => {
    const startMs = endMs - SPAN;
    const visible = eventsIn(startMs - 1, endMs - LAG);
    const buckets: HistogramBucket[] = [];
    for (let b = Math.floor(startMs / BUCKET) * BUCKET; b <= endMs; b += BUCKET) {
      buckets.push({ time: new Date(b).toISOString(), count: visible.filter((t) => t >= b && t < b + BUCKET).length });
    }
    return buckets;
  };
  /** Events that became visible in (prev, now] and the feed delivered (it drops every fifth). */
  const feed = (prevMs: number, nowMs: number) =>
    eventsIn(prevMs - LAG, nowMs - LAG).filter((t) => Math.round((t - ORIGIN) / EVERY_MS) % 5 !== 0);
  const sum = (h: HistogramBucket[]) => h.reduce((n, b) => n + b.count, 0);

  function run(reanchor: boolean) {
    let histogram = serverAt(START);
    let cutoff = START - LAG;
    let log: number[] = [];
    let lastAnchor = 0;
    const samples: Array<{ shown: number; truth: number }> = [];
    for (let now = START + TICK; now <= START + 70 * MIN; now += TICK) {
      const arrivals = feed(now - TICK, now);
      logTailArrivals(log, arrivals, cutoff);
      histogram = advanceTailHistogram(histogram, arrivals, { nowMs: now, countAfterMs: cutoff, windowStartMs: now - SPAN });
      if (reanchor && tailReanchorDue(lastAnchor, now, SPAN, TICK)) {
        lastAnchor = now;
        const next = reanchorTailHistogram(serverAt(now), log, { anchorEndMs: now, nowMs: now, windowStartMs: now - SPAN });
        histogram = next.histogram;
        log = next.arrivalLog;
        cutoff = now;
      }
      samples.push({ shown: sum(histogram), truth: truth(now) });
    }
    return samples;
  }

  it('without re-anchoring the count saw-tooths and drifts low (the bug)', () => {
    const samples = run(false);
    const worst = Math.max(...samples.map((s) => s.truth - s.shown));
    const biggestDrop = Math.max(...samples.slice(1).map((s, i) => samples[i].shown - s.shown));
    expect(worst).toBeGreaterThan(0.15 * truth(START));
    expect(biggestDrop).toBeGreaterThan(3 * PER_MIN);
  });

  it('re-anchored, the count tracks [now - 1h, now] within the lake lag and never saw-tooths', () => {
    const samples = run(true);
    for (const { shown, truth: expected } of samples) {
      // Lake lag (1 min) plus one re-anchor interval of a lossy feed.
      expect(Math.abs(expected - shown)).toBeLessThanOrEqual(2 * PER_MIN);
    }
    const biggestDrop = Math.max(...samples.slice(1).map((s, i) => samples[i].shown - s.shown));
    expect(biggestDrop).toBeLessThanOrEqual(PER_MIN);
  });
});

describe('rolling range label (NAN-3263)', () => {
  it('names the span the tail is rolling', () => {
    expect(tailRollingRangeLabel(60 * MIN)).toBe('Last 1h · live');
    expect(tailRollingRangeLabel(15 * MIN)).toBe('Last 15m · live');
    expect(tailRollingRangeLabel(24 * 60 * MIN)).toBe('Last 1d · live');
  });
  it('keeps at most two units', () => {
    expect(formatTailSpan(90 * MIN)).toBe('1h 30m');
    expect(formatTailSpan(90 * MIN + 7_000)).toBe('1h 30m');
    expect(formatTailSpan(45_000)).toBe('45s');
    expect(formatTailSpan(0)).toBe('0s');
  });
});

// NAN-3267: one live sample read "0 events" between 80,582 and 82,259.
describe('tailReanchorTrusted', () => {
  const window = { anchorStartMs: T0, anchorEndMs: T0 + 10 * MIN };
  const live = serverHistogram([5, 7, 9, 11, 0, 0, 3, 4, 6, 8]);

  it('never trusts an empty, missing, or unparseable read', () => {
    expect(tailReanchorTrusted([], live, window)).toBe(false);
    expect(tailReanchorTrusted(undefined, live, window)).toBe(false);
    expect(tailReanchorTrusted(null, live, window)).toBe(false);
    expect(tailReanchorTrusted([{ time: 'not a time', count: 5 }], live, window)).toBe(false);
  });

  it('always trusts a read with events, even a lower one', () => {
    expect(tailReanchorTrusted(serverHistogram([1, 0, 0]), live, window)).toBe(true);
    expect(tailReanchorTrusted(serverHistogram([100, 200]), [], window)).toBe(true);
  });

  it('rejects an all-zero read over buckets that already hold events in the window', () => {
    expect(tailReanchorTrusted(serverHistogram(Array(10).fill(0)), live, window)).toBe(false);
  });

  it('accepts a real zero: nothing on screen sits inside the anchored window', () => {
    const zeros = serverHistogram(Array(10).fill(0));
    // The source went quiet: every bucket on screen is already zero.
    expect(tailReanchorTrusted(zeros, serverHistogram(Array(10).fill(0)), window)).toBe(true);
    // Or the only events are older than the anchored window's start.
    const later = { anchorStartMs: T0 + 2 * MIN, anchorEndMs: T0 + 12 * MIN };
    expect(tailReanchorTrusted(zeros, serverHistogram([5, 7, 0, 0, 0]), later)).toBe(true);
    // Or the timeline is still empty.
    expect(tailReanchorTrusted(zeros, [], window)).toBe(true);
  });

  it('does not let tail arrivals after the anchor end veto a zero read', () => {
    // Only the newest bucket (ending past the anchor) holds events.
    const pending = serverHistogram([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4]);
    expect(tailReanchorTrusted(serverHistogram(Array(10).fill(0)), pending, window)).toBe(true);
  });
});


describe('tailHistogramCutoff', () => {
  it('excludes events already counted beyond the newest displayed row', () => {
    const queryEndMs = T0 + 4 * MIN;
    const histogram = [
      { time: new Date(T0 - 5 * MIN).toISOString(), count: 14_000 },
      { time: new Date(T0).toISOString(), count: 13_000 },
    ];
    // A page can lag the query end; the feed delivers unseen rows from that
    // gap even though the raw histogram already counted them.
    const cutoff = tailHistogramCutoff(T0 + 2 * MIN, queryEndMs);
    const out = advanceTailHistogram(histogram, [T0 + 3 * MIN, queryEndMs, queryEndMs + 1], {
      nowMs: queryEndMs + 1, countAfterMs: cutoff,
    });
    expect(out[1].count).toBe(13_001);
    expect(out.reduce((sum, b) => sum + b.count, 0)).toBe(27_001);
  });

  it('preserves a later reanchor when the tail re-arms and ignores invalid ends', () => {
    expect(tailHistogramCutoff(T0 + 5 * MIN, T0 + 4 * MIN)).toBe(T0 + 5 * MIN);
    expect(tailHistogramCutoff(T0, Number.NaN)).toBe(T0);
  });
});
