// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from 'vitest';
import { formatTimelineAxisLabel, formatTimelineTooltipTime, timelineAxisTicks } from './timeline-axis';
import { buildSearchTimeline } from '@/pages/search-timeline';

// NAN-5320: a multi-year Event Stream window drew today's only event near the
// LEFT edge and cycled yearless tick labels.

const START = Date.parse('2000-01-01T00:00:00Z');
const END = Date.parse('2026-11-12T12:00:00Z');

describe('multi-year histogram', () => {
  it('keeps every daily bucket at its own time (no merge across years)', () => {
    const histogramData: { time: string; count: number }[] = [];
    for (let t = START; t <= Date.parse('2026-11-12T00:00:00Z'); t += 86_400_000) {
      histogramData.push({ time: new Date(t).toISOString(), count: 0 });
    }
    histogramData[histogramData.length - 1].count = 1;
    const timeline = buildSearchTimeline({
      histogramData,
      results: [],
      isAggregateQuery: false,
      spansDays: true,
      showSeconds: false,
    });
    expect(timeline).toHaveLength(histogramData.length);
    const hits = timeline.filter((p) => p.events > 0);
    expect(hits).toHaveLength(1);
    expect(hits[0].timestamp).toBe(Date.parse('2026-11-12T00:00:00Z'));
  });

  it('still sums duplicate buckets with the same start', () => {
    const timeline = buildSearchTimeline({
      histogramData: [
        { time: '2026-11-12T00:00:00Z', count: 2 },
        { time: '2026-11-12T00:00:00Z', count: 3 },
      ],
      results: [],
      isAggregateQuery: false,
      spansDays: true,
      showSeconds: false,
    });
    expect(timeline).toEqual([expect.objectContaining({ timestamp: Date.parse('2026-11-12T00:00:00Z'), events: 5 })]);
  });
});

describe('timelineAxisTicks', () => {
  it('steps a multi-year window by calendar years, ~20 ticks, with distinct labels', () => {
    const ticks = timelineAxisTicks(START, END);
    expect(ticks.length).toBeGreaterThan(5);
    expect(ticks.length).toBeLessThanOrEqual(30);
    for (const t of ticks) {
      const d = new Date(t);
      expect(d.getUTCDate()).toBe(1);
      expect(d.getUTCHours()).toBe(0);
    }
    const labels = ticks.map((t) => formatTimelineAxisLabel(t, START, END));
    expect(new Set(labels).size).toBe(labels.length);
    expect(labels[0]).toBe('Jan 2000');
  });

  it('keeps fixed steps on a short window', () => {
    const s = Date.parse('2026-11-12T00:00:00Z');
    const ticks = timelineAxisTicks(s, s + 3_600_000);
    expect(ticks[1] - ticks[0]).toBe(5 * 60_000);
    expect(formatTimelineAxisLabel(ticks[1], s, s + 3_600_000)).toBe('00:05');
  });

  it('labels a multi-day window that crosses a year with the year', () => {
    const s = Date.parse('2025-12-28T00:00:00Z');
    const e = Date.parse('2026-01-04T00:00:00Z');
    expect(formatTimelineAxisLabel(Date.parse('2026-01-01T00:00:00Z'), s, e)).toBe('1/1/26 00:00');
    expect(formatTimelineTooltipTime(Date.parse('2026-01-01T06:00:00Z'), s, e)).toBe('Jan 1 2026, 06:00');
  });

  it('keeps the yearless multi-day label within one year', () => {
    const s = Date.parse('2026-11-05T00:00:00Z');
    const e = Date.parse('2026-11-12T00:00:00Z');
    expect(formatTimelineAxisLabel(Date.parse('2026-11-08T00:00:00Z'), s, e)).toBe('11/8 00:00');
  });

  it('returns no ticks for an empty or inverted window', () => {
    expect(timelineAxisTicks(10, 10)).toEqual([]);
    expect(timelineAxisTicks(10, 5)).toEqual([]);
  });
});
