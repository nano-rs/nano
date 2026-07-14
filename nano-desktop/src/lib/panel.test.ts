import { describe, expect, it } from 'vitest';

import { classify, densify, preparePanelData } from './panel';
import type { PanelQueryResponse } from './types';

const response = (partial: Partial<PanelQueryResponse>): PanelQueryResponse => ({
  results: [],
  total_count: 0,
  execution_time_ms: 1,
  ...partial,
});

/**
 * A chart that plots the wrong column doesn't crash — it renders a confident,
 * plausible lie. These tests exist to keep it honest.
 */

describe('classify — which column is the label and which is the measure', () => {
  it('uses column_order to tell a numeric GROUP-BY from a numeric AGGREGATE', () => {
    // `stats count by dest_port` — both columns are numbers. Serde alphabetises the
    // keys, so `count` arrives FIRST. Without column_order a renderer plots the
    // port number as the bar height.
    const data = classify(
      response({
        results: [
          { count: 42, dest_port: 443 },
          { count: 7, dest_port: 22 },
        ],
        column_order: ['dest_port', 'count'],
      })
    );

    expect(data.labelKey).toBe('dest_port');
    expect(data.valueKeys).toEqual(['count']);
  });

  it('still finds the measure when the server sends no column_order', () => {
    const data = classify(
      response({ results: [{ count: 3, source_type: 'tenzir' }] })
    );
    expect(data.labelKey).toBe('source_type');
    expect(data.valueKeys).toEqual(['count']);
  });

  it('recognises a time bucket as the x-axis whatever the order says', () => {
    const data = classify(
      response({
        results: [{ count: 1, time_bucket: '2026-07-13T00:00:00Z' }],
        column_order: ['time_bucket', 'count'],
      })
    );
    expect(data.labelKey).toBe('time_bucket');
    expect(data.isTime).toBe(true);
  });

  it('falls back to any numeric column when nothing looks like a named aggregate', () => {
    const data = classify(
      response({ results: [{ host: 'web-01', total_bytes: 900 }], column_order: ['host', 'total_bytes'] })
    );
    expect(data.labelKey).toBe('host');
    expect(data.valueKeys).toEqual(['total_bytes']);
  });

  it('handles an empty result set without inventing columns', () => {
    const data = classify(response({ results: [] }));
    expect(data.valueKeys).toEqual([]);
  });
});

describe('classify — a panel with no group-by still has a number', () => {
  it('does not consume the only measure as the label (`| stats count`)', () => {
    // The canonical single_value panel. Treating column_order[0] as the label ate
    // the count, and the tile rendered "No numeric value" for a perfectly good number.
    const data = classify(response({ results: [{ count: 12345 }], column_order: ['count'] }));
    expect(data.labelKey).toBe('');
    expect(data.valueKeys).toEqual(['count']);
  });

  it('keeps every measure when there is no dimension at all', () => {
    // `| stats count, avg(bytes)` — the tile must show the COUNT, not the average.
    const data = classify(
      response({
        results: [{ count: 10, avg_bytes: 900 }],
        column_order: ['count', 'avg_bytes'],
      })
    );
    expect(data.labelKey).toBe('');
    expect(data.valueKeys).toEqual(['count', 'avg_bytes']);
  });
});

describe('pivotSplitBy — a split-by series must not overwrite itself', () => {
  it('pivots a NUMERIC split-by, which is where a chart lies loudest', () => {
    // `timechart count by status_code`. The split column is a number, so a
    // "dimensions are the non-numeric columns" rule left it in long form — and
    // densify's bucket map then kept only the LAST row per bucket. The chart drew
    // the 5xx counts as the total traffic line.
    const data = preparePanelData(
      response({
        results: [
          { time_bucket: '2026-07-13T00:00:00Z', status_code: 200, count: 100 },
          { time_bucket: '2026-07-13T00:00:00Z', status_code: 500, count: 3 },
          { time_bucket: '2026-07-13T01:00:00Z', status_code: 200, count: 120 },
          { time_bucket: '2026-07-13T01:00:00Z', status_code: 500, count: 7 },
        ],
        column_order: ['time_bucket', 'status_code', 'count'],
      })
    );

    expect(data.rows).toHaveLength(2);
    expect(data.valueKeys.sort()).toEqual(['200', '500']);
    expect(data.rows[0]).toMatchObject({ '200': 100, '500': 3 });
    expect(data.rows[1]).toMatchObject({ '200': 120, '500': 7 });
  });

  it('turns `timechart count by action` from long into wide', () => {
    // Long form: one row per (bucket, action). Charted as-is, each bucket keeps
    // only the LAST action's value and the other series vanish.
    const data = preparePanelData(
      response({
        results: [
          { time_bucket: '2026-07-13T00:00:00Z', action: 'allow', count: 10 },
          { time_bucket: '2026-07-13T00:00:00Z', action: 'deny', count: 2 },
          { time_bucket: '2026-07-13T01:00:00Z', action: 'allow', count: 12 },
          { time_bucket: '2026-07-13T01:00:00Z', action: 'deny', count: 3 },
        ],
        column_order: ['time_bucket', 'action', 'count'],
      })
    );

    expect(data.rows).toHaveLength(2);
    expect(data.valueKeys.sort()).toEqual(['allow', 'deny']);
    expect(data.rows[0]).toMatchObject({ allow: 10, deny: 2 });
    expect(data.rows[1]).toMatchObject({ allow: 12, deny: 3 });
  });
});

describe('densify — the quiet buckets are part of the truth', () => {
  it('fills the gaps a timechart omitted', () => {
    // A timechart only returns buckets that HAD events. Plotted as-is, 00:00 and
    // 03:00 become adjacent points and the line reads as a rate that never dipped.
    const data = densify(
      classify(
        response({
          results: [
            { time_bucket: '2026-07-13T00:00:00Z', count: 5 },
            { time_bucket: '2026-07-13T01:00:00Z', count: 4 },
            { time_bucket: '2026-07-13T03:00:00Z', count: 9 },
          ],
          column_order: ['time_bucket', 'count'],
        })
      )
    );

    expect(data.rows).toHaveLength(4); // 00, 01, 02, 03
    expect(data.rows[2].count).toBe(0); // 02:00 had no events — that IS zero
  });

  it('fills a missing AVERAGE with null, not zero', () => {
    // The average of no events is undefined, not zero. Drawing it as zero invents
    // a dip to the floor that never happened.
    // Three points establish a 1h span, with 02:00 missing from it.
    const data = densify(
      classify(
        response({
          results: [
            { time_bucket: '2026-07-13T00:00:00Z', avg_duration: 30 },
            { time_bucket: '2026-07-13T01:00:00Z', avg_duration: 35 },
            { time_bucket: '2026-07-13T03:00:00Z', avg_duration: 40 },
          ],
          column_order: ['time_bucket', 'avg_duration'],
        })
      )
    );

    expect(data.rows).toHaveLength(4);
    expect(data.rows[2].avg_duration).toBeNull();
  });

  it('leaves a non-time series alone', () => {
    const data = preparePanelData(
      response({
        results: [
          { source_type: 'tenzir', count: 3 },
          { source_type: 'apache', count: 2 },
        ],
        column_order: ['source_type', 'count'],
      })
    );
    expect(data.rows).toHaveLength(2);
  });

  it('zero-fills a pivoted COUNT series, keyed on the measure and not the group name', () => {
    // After a pivot the series are called `allow`/`deny`, which say nothing about
    // whether an absent bucket is zero. Testing THOSE names always said "no", so a
    // quiet hour of a count series became a hole in the line instead of a zero.
    // Three buckets establish a 1h span, with 02:00 missing from it.
    const data = preparePanelData(
      response({
        results: [
          { time_bucket: '2026-07-13T00:00:00Z', action: 'allow', count: 10 },
          { time_bucket: '2026-07-13T00:00:00Z', action: 'deny', count: 2 },
          { time_bucket: '2026-07-13T01:00:00Z', action: 'allow', count: 11 },
          { time_bucket: '2026-07-13T01:00:00Z', action: 'deny', count: 1 },
          { time_bucket: '2026-07-13T03:00:00Z', action: 'allow', count: 12 },
          { time_bucket: '2026-07-13T03:00:00Z', action: 'deny', count: 3 },
        ],
        column_order: ['time_bucket', 'action', 'count'],
      })
    );

    // 02:00 was quiet. For a COUNT that is a zero, not a gap in the line.
    expect(data.rows).toHaveLength(4);
    expect(data.rows[2]).toMatchObject({ allow: 0, deny: 0 });
  });

  it('does not destroy unevenly-spaced buckets (span=1mon)', () => {
    // Monthly buckets are 28/30/31 days apart. Walking a grid built from the
    // SMALLEST gap missed every real bucket after the first and zero-filled in
    // their place: five real data points became one value and four invented zeros.
    const data = densify(
      classify(
        response({
          results: [
            { time_bucket: '2026-01-01T00:00:00Z', count: 10 },
            { time_bucket: '2026-02-01T00:00:00Z', count: 20 },
            { time_bucket: '2026-03-01T00:00:00Z', count: 30 },
            { time_bucket: '2026-04-01T00:00:00Z', count: 40 },
          ],
          column_order: ['time_bucket', 'count'],
        })
      )
    );

    expect(data.rows.map((row) => row.count)).toEqual([10, 20, 30, 40]);
  });

  it('refuses to fabricate a million points from a pathological span', () => {
    const data = densify(
      classify(
        response({
          results: [
            { time_bucket: '2020-01-01T00:00:00Z', count: 1 },
            { time_bucket: '2020-01-01T00:00:01Z', count: 1 },
            { time_bucket: '2026-01-01T00:00:00Z', count: 1 },
          ],
          column_order: ['time_bucket', 'count'],
        })
      )
    );
    // A 1-second span across six years would be ~190 million points.
    expect(data.rows).toHaveLength(3);
  });
});
