// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from 'vitest';
import { buildSearchTimeline } from './search-timeline';

const base = { spansDays: false, showSeconds: false };

describe('buildSearchTimeline (NAN-3062)', () => {
  it('uses the server histogram for an aggregate query, not the stats rows', () => {
    const timeline = buildSearchTimeline({
      ...base,
      isAggregateQuery: true,
      histogramData: [
        { time: '2026-09-29T10:05:00Z', count: 4 },
        { time: '2026-09-29T10:00:00Z', count: 7 },
      ],
      results: [
        { fields: { 'device.hostname': 'ws1', count: 9 } },
        { fields: { 'device.hostname': 'ws2', count: 2 } },
      ],
    });
    expect(timeline.map((p) => p.events)).toEqual([7, 4]);
    expect(timeline[0].timestamp).toBe(Date.parse('2026-09-29T10:00:00Z'));
  });

  it('renders no timeline for stats rows without a histogram (no single "now" dot)', () => {
    expect(
      buildSearchTimeline({
        ...base,
        isAggregateQuery: true,
        histogramData: [],
        results: [
          { fields: { 'device.hostname': 'ws1', count: 9 } },
          { fields: { 'device.hostname': 'ws2', count: 2 } },
        ],
      }),
    ).toEqual([]);
  });

  it('renders no placeholder timeline for an empty aggregate result', () => {
    expect(
      buildSearchTimeline({ ...base, isAggregateQuery: true, histogramData: [], results: [] }),
    ).toEqual([]);
  });

  it('never builds a timeline from a paginated event page', () => {
    expect(
      buildSearchTimeline({
        ...base,
        isAggregateQuery: false,
        histogramData: [],
        results: [{ fields: { time: '2026-09-29T10:00:00Z' } }],
      }),
    ).toEqual([]);
  });

  it('keeps the timechart time_bucket rows as a real time axis', () => {
    const timeline = buildSearchTimeline({
      ...base,
      isAggregateQuery: true,
      histogramData: [],
      results: [
        { fields: { time_bucket: '2026-09-29 11:00:00', count: 3 } },
        { fields: { time_bucket: '2026-09-29 10:00:00', 'count()': 5 } },
      ],
    });
    expect(timeline.map((p) => p.events)).toEqual([5, 3]);
    expect(timeline[0].timestamp).toBe(Date.parse('2026-09-29T10:00:00Z'));
  });
});
