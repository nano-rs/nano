// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-5612: a timechart split by a field keeps its legend when only one series
 * is in the window (a scoped viewer seeing only `high` detections), while a
 * plain single-aggregate chart stays legend-free.
 */
import { describe, expect, it } from 'vitest';
import { pivotSplitByData, seriesNeedLegend } from './VisualizationRenderer';

describe('series legend', () => {
  it('keeps the legend for one split series from the server timechart', () => {
    const rows = [{ _timechart: { span_seconds: 3600 }, time_bucket: '2026-11-18T00:00:00Z', high: 3 }];
    const p = pivotSplitByData(rows);
    expect(p.valueKeys).toEqual(['high']);
    expect(p.splitSeries).toBe(true);
    expect(seriesNeedLegend(p.valueKeys, p.splitSeries)).toBe(true);
  });

  it('keeps the legend for one pivoted split series', () => {
    const rows = [
      { time_bucket: '2026-11-18T00:00:00Z', severity: 'high', count: 2 },
      { time_bucket: '2026-11-18T01:00:00Z', severity: 'high', count: 1 },
    ];
    const p = pivotSplitByData(rows, ['time_bucket', 'severity', 'count']);
    expect(p.valueKeys).toEqual(['high']);
    expect(seriesNeedLegend(p.valueKeys, p.splitSeries)).toBe(true);
  });

  it('has no legend for a single plain aggregate', () => {
    const server = pivotSplitByData([{ _timechart: { span_seconds: 3600 }, time_bucket: '2026-11-18T00:00:00Z', count: 3 }]);
    expect(seriesNeedLegend(server.valueKeys, server.splitSeries)).toBe(false);
    const stats = pivotSplitByData([{ entity_type: 'user', count: 2 }], ['entity_type', 'count']);
    expect(seriesNeedLegend(stats.valueKeys, stats.splitSeries)).toBe(false);
  });

  it('always shows a legend for several series', () => {
    expect(seriesNeedLegend(['critical', 'high'], true)).toBe(true);
    expect(seriesNeedLegend(['count', 'avg_bytes'], false)).toBe(true);
  });
});
