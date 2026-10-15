// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { Curve } from 'recharts';
import { buildTimelinePlotData, timelinePlotDomain, timelineSeriesData, resolveBucketStart, type TimelineBucket } from './timeline-fill';

// NAN-3253: the live repro — 1h window 22:36:42 → 23:36:42, 5-min buckets
// keyed by start, 22:35 … 23:35 (13 buckets). The rendered domain is the
// picker window unioned with the bucket extent (starts at 22:35).
const MIN = 60_000;
const BUCKET = 5 * MIN;
const T0 = Date.UTC(2026, 9, 6, 22, 35, 0);
const WINDOW: [number, number] = [Date.UTC(2026, 9, 6, 22, 36, 42), Date.UTC(2026, 9, 6, 23, 36, 42)];
const DOMAIN: [number, number] = [T0, WINDOW[1]];

const buckets: TimelineBucket[] = Array.from({ length: 13 }, (_, i) => ({
  time: `b${i}`,
  timestamp: T0 + i * BUCKET,
  events: i === 0 ? 3900 : i === 12 ? 1200 : 5300,
}));

describe('buildTimelinePlotData', () => {
  it('handles empty data', () => {
    for (const chartType of ['bar', 'line', 'area'] as const) {
      expect(buildTimelinePlotData([], { bucketMs: BUCKET, domain: DOMAIN, window: WINDOW, chartType })).toEqual([]);
    }
  });

  it('static mode is a no-op: one point per bucket at its timestamp, nothing partial', () => {
    const out = buildTimelinePlotData(buckets, {
      bucketMs: BUCKET,
      domain: DOMAIN,
      window: WINDOW,
      chartType: 'area',
      staticMode: true,
    });
    expect(out).toHaveLength(buckets.length);
    out.forEach((p, i) => {
      expect(p.x).toBe(buckets[i].timestamp);
      expect(p.timestamp).toBe(buckets[i].timestamp);
      expect(p.events).toBe(buckets[i].events);
      expect(p.partial).toBe(false);
    });
  });

  it('line/area: has one raw point per bucket spanning query edges', () => {
    for (const chartType of ['line', 'area'] as const) {
      const out = buildTimelinePlotData(buckets, { bucketMs: BUCKET, domain: DOMAIN, window: WINDOW, chartType });
      expect(out).toHaveLength(buckets.length);
      expect(out[0].x).toBe(WINDOW[0]);
      expect(out.at(-1)!.x).toBe(WINDOW[1]);
      out.forEach(p => {
        expect(p).not.toHaveProperty('synthetic');

      });
      expect(out.reduce((sum, p) => sum + p.events, 0)).toBe(buckets.reduce((sum, p) => sum + p.events, 0));
    }
  });

  it('places aligned final bucket at query end', () => {
    const domain: [number, number] = [T0, T0 + 13 * BUCKET];
    const out = buildTimelinePlotData(buckets, { bucketMs: BUCKET, domain, window: domain, chartType: 'line' });
    expect(out.at(-1)!.x).toBe(domain[1]);
  });

  it('bar: each bar is centred on its bucket so it spans [start, start + interval]', () => {
    const out = buildTimelinePlotData(buckets, { bucketMs: BUCKET, domain: DOMAIN, window: WINDOW, chartType: 'bar' });
    expect(out).toHaveLength(buckets.length);
    out.forEach((p, i) => {
      expect(p.x).toBe(buckets[i].timestamp + BUCKET / 2);
    });
    // The last bar's right edge covers the domain end.
    expect(out[12].x + BUCKET / 2).toBeGreaterThanOrEqual(DOMAIN[1]);
  });

  it('flags partial first and last buckets without altering counts', () => {
    for (const chartType of ['bar', 'line', 'area'] as const) {
      const out = buildTimelinePlotData(buckets, { bucketMs: BUCKET, domain: DOMAIN, window: WINDOW, chartType });
      const real = out;
      expect(real[0].partial).toBe(true);
      expect(real[real.length - 1].partial).toBe(true);
      expect(real.slice(1, -1).every((p) => !p.partial)).toBe(true);
      real.forEach((p, i) => expect(p.events).toBe(buckets[i].events));
    }
  });

  it('does not flag aligned edge buckets', () => {
    const window: [number, number] = [T0, T0 + 13 * BUCKET];
    const out = buildTimelinePlotData(buckets, { bucketMs: BUCKET, domain: window, window, chartType: 'bar' });
    expect(out.some((p) => p.partial)).toBe(false);
  });

  it('does not flag a bucket the window boundary falls outside of (NAN-1454 widened search)', () => {
    // Picker window starts well after the first bucket ends.
    const window: [number, number] = [T0 + 30 * MIN, WINDOW[1]];
    const out = buildTimelinePlotData(buckets, { bucketMs: BUCKET, domain: DOMAIN, window, chartType: 'bar' });
    expect(out[0].partial).toBe(false);
  });

  it.each(['bar', 'line', 'area'] as const)('preserves a tall trailing raw count in %s, with coverage and sum invariance', chartType => {
    const data = buckets.map((b, i) => ({ ...b, events: i === 12 ? 15_000 : b.events }));
    const window: [number, number] = [T0 + 4 * MIN, T0 + 64 * MIN];
    const out = buildTimelinePlotData(data, { bucketMs: BUCKET, domain: window, window, chartType });
    expect(out[0].partialSpan).toEqual([window[0], T0 + BUCKET]);
    expect(out[0].partialLabel).toBe('partial bucket · 1 of 5 min in range');
    expect(out.at(-1)!.partialLabel).toBe('partial bucket · 4 of 5 min in range');
    expect(out.at(-1)!.events).toBe(15_000);
    expect(out.reduce((n, p) => n + p.events, 0)).toBe(data.reduce((n, b) => n + b.events, 0));
    if (chartType !== 'bar') expect(out[0].x).toBe(window[0]);
  });

  it.each(['leading', 'trailing'] as const)('flags only the %s partial edge', edge => {
    const window: [number, number] = [T0 + (edge === 'leading' ? MIN : 0), T0 + 13 * BUCKET - (edge === 'trailing' ? MIN : 0)];
    const out = buildTimelinePlotData(buckets, { bucketMs: BUCKET, domain: window, window, chartType: 'area' });
    expect(out.filter(p => p.partial).map(p => p.timestamp)).toEqual([buckets[edge === 'leading' ? 0 : 12].timestamp]);
  });

  it('single bucket remains one point, including when both ends are partial', () => {
    const window: [number, number] = [T0 + MIN, T0 + 4 * MIN];
    const out = buildTimelinePlotData([buckets[0]], { bucketMs: BUCKET, domain: window, window, chartType: 'line' });
    expect(out).toHaveLength(1);
    expect(out[0].x).toBe(window[0]);
    expect(out[0].events).toBe(3900);
    expect(out[0].partialSpan).toEqual(window);
  });
});

describe('resolveBucketStart', () => {
  const out = buildTimelinePlotData(buckets, { bucketMs: BUCKET, domain: DOMAIN, window: WINDOW, chartType: 'line' });

  it('maps the active index back to the bucket start', () => {
    expect(resolveBucketStart(out, { activeTooltipIndex: 0 })).toBe(buckets[0].timestamp);
    expect(resolveBucketStart(out, { activeTooltipIndex: '3' })).toBe(buckets[3].timestamp);
    expect(resolveBucketStart(out, { activeTooltipIndex: out.length - 1 })).toBe(buckets[12].timestamp);
  });

  it.each(['bar', 'line', 'area'] as const)('maps click/drag activeIndex in %s to the bucket start', chartType => {
    const points = buildTimelinePlotData(buckets, { bucketMs: BUCKET, domain: DOMAIN, window: WINDOW, chartType });
    expect(resolveBucketStart(points, { activeIndex: '0' })).toBe(T0);
    expect(resolveBucketStart(points, { activeIndex: String(points.length - 1) })).toBe(buckets[12].timestamp);
  });

  it('falls back to the active label (x) when no index is given', () => {
    expect(resolveBucketStart(out, { activeLabel: out[4].x })).toBe(out[4].timestamp);
  });

  it('returns undefined when nothing is active', () => {
    expect(resolveBucketStart(out, undefined)).toBeUndefined();
    expect(resolveBucketStart(out, { activeTooltipIndex: undefined, activeLabel: undefined })).toBeUndefined();
    expect(resolveBucketStart(out, { activeTooltipIndex: 999 })).toBeUndefined();
  });
});


it.each([1200, 15000])('monotone edge segments stay within the raw endpoint counts (trailing %i)', trailing => {
  const data = buckets.map((b, i) => ({ ...b, events: i === 12 ? trailing : b.events }));
  const window: [number, number] = [T0 + 4 * MIN, T0 + 64 * MIN];
  const points = buildTimelinePlotData(data, { bucketMs: BUCKET, domain: DOMAIN, window, chartType: 'line' });
  const markup = renderToStaticMarkup(createElement(Curve, {
    type: 'monotone', layout: 'horizontal',
    points: points.map(p => ({ x: (p.x - T0) / MIN, y: p.events })),
  }));
  const path = markup.match(/ d="([^"]+)"/)![1];
  const segments = path.split('C').slice(1).map(segment => segment.match(/-?[\d.]+(?:e[+-]?\d+)?/gi)!.map(Number));
  expect(segments).toHaveLength(points.length - 1);
  for (const i of [0, segments.length - 1]) {
    const [x1, y1, x2, y2, x3, y3] = segments[i];
    const x0 = (points[i].x - T0) / MIN;
    const y0 = points[i].events;
    const bezier = (a: number, b: number, c: number, d: number, t: number) =>
      (1 - t) ** 3 * a + 3 * (1 - t) ** 2 * t * b + 3 * (1 - t) * t ** 2 * c + t ** 3 * d;
    for (let j = 0; j <= 100; j++) {
      const t = j / 100;
      const x = bezier(x0, x1, x2, x3, t);
      const y = bezier(y0, y1, y2, y3, t);
      expect(x).toBeGreaterThanOrEqual(x0 - 0.001);
      expect(x).toBeLessThanOrEqual(x3 + 0.001);
      expect(y).toBeGreaterThanOrEqual(Math.min(y0, y3) - 0.001);
      expect(y).toBeLessThanOrEqual(Math.max(y0, y3) + 0.001);
    }
  }
});

describe('line/area edge contract', () => {
  it.each(['line', 'area'] as const)('%s domain is exactly 11:27–12:27', chartType => {
    const start = Date.UTC(2026, 9, 13, 11, 25);
    const window: [number, number] = [start + 2 * MIN, start + 62 * MIN];
    expect(timelinePlotDomain(chartType, window, [start, window[1]])).toEqual(window);
    const points = buildTimelinePlotData(buckets.map((p, i) => ({...p, timestamp: start + i * BUCKET})), {bucketMs: BUCKET, domain: window, window, chartType});
    expect(points[0].x).toBe(window[0]);
    expect(points.at(-1)!.x).toBe(window[1]);
    expect(points[0].solid).toBeNull();
    expect(points[1].leadingPartial).toBe(points[1].events);
    expect(points[2].leadingPartial).toBeNull();
    expect(points.at(-2)!.trailingPartial).toBe(points.at(-2)!.events);
    expect(points.at(-1)!.solid).toBeNull();
    expect(points[0].partialLabel).toBe('partial bucket · 3 of 5 min in range');
    expect(points.at(-1)!.partialLabel).toBe('partial bucket · 2 of 5 min in range');
    expect(resolveBucketStart(points, {activeLabel: window[0]})).toBe(start);
    expect(resolveBucketStart(points, {activeLabel: window[1]})).toBe(start + 60 * MIN);
  });
  it('bar domain preserves bucket extent', () => {
    expect(timelinePlotDomain('bar', WINDOW, DOMAIN)).toEqual(DOMAIN);
  });
  it('four buckets keep the full middle connection solid', () => {
    const window: [number, number] = [T0 + MIN, T0 + 19 * MIN];
    const p = buildTimelinePlotData(buckets.slice(0,4), {bucketMs: BUCKET, domain: window, window, chartType: 'area'});
    expect(p.map(p => p.leadingPartial)).toEqual([3900,5300,null,null]);
    expect(p.map(p => p.trailingPartial)).toEqual([null,null,5300,5300]);
  });
});

it('single-bucket rendering spans the range without duplicating accounting or zoom identity', () => {
 const window: [number, number] = [T0 + MIN, T0 + 4 * MIN];
 const points = buildTimelinePlotData([buckets[0]], {bucketMs: BUCKET, domain: window, window, chartType: 'area'});
 const series = timelineSeriesData(points, 'area', window);
 expect(series.map(p => p.x)).toEqual(window);
 expect(points.reduce((sum,p) => sum+p.events,0)).toBe(3900);
 expect(resolveBucketStart(series, {activeIndex: 1})).toBe(T0);
 expect(timelineSeriesData(points, 'bar', window)).toBe(points);
});
