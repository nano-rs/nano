// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// NAN-5699: the timechart and top/rare Export buttons had no click handler.
// They now download the chart's series / the ranked table as CSV.
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const dl = vi.hoisted(() => ({ download: vi.fn() }));
vi.mock('@/lib/csv-download', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/lib/csv-download')>();
  return { ...actual, downloadCsv: dl.download };
});
vi.mock('recharts', async (importOriginal) => {
  const actual = await importOriginal<typeof import('recharts')>();
  // jsdom has no layout: render the chart container as a plain box.
  return { ...actual, ResponsiveContainer: ({ children }: { children: React.ReactNode }) => <div>{children}</div> };
});

import { TimechartView, parseTimeBucket, timechartCsv, transformResults } from './TimechartView';
import { RankedBarChart, rankedCsv, transform } from './RankedBarChart';

const r = (fields: Record<string, unknown>, i: number) => ({ id: `r${i}`, timestamp: new Date(), source: 's', fields });

const buckets = [
  { time_bucket: '2026-11-18 06:00:00', count: 4 },
  { time_bucket: '2026-11-18 00:00:00', count: 7 },
].map(r);

const split = [
  { time_bucket: '2026-11-18 00:00:00', user: 'alice', count: 2 },
  { time_bucket: '2026-11-18 00:00:00', user: 'bob', count: 5 },
  { time_bucket: '2026-11-18 06:00:00', user: 'alice', count: 1 },
].map(r);

const top = [
  { 'actor.user.name': 'judy.chen', count: 6, percent: 60 },
  { 'actor.user.name': '=HYPERLINK("x")', count: 4, percent: 40 },
].map(r);

afterEach(cleanup);
beforeEach(() => dl.download.mockReset());

describe('timechart CSV', () => {
  it('has one row per bucket in time order with the series as columns', () => {
    const csv = timechartCsv(transformResults(buckets));
    const lines = csv.split('\n');
    expect(lines[0]).toBe('time_bucket,count');
    // ClickHouse buckets are naive UTC: exported as that exact UTC instant,
    // whatever the browser's timezone (the suite also runs under TZ=Asia/Tokyo).
    expect(lines.slice(1)).toEqual(['2026-11-18T00:00:00.000Z,7', '2026-11-18T06:00:00.000Z,4']);
  });

  it('reads naive, Z-suffixed and epoch buckets as UTC and drops unusable ones', () => {
    expect(parseTimeBucket('2026-11-18 06:00:00')).toBe(Date.UTC(2026, 10, 18, 6));
    expect(parseTimeBucket('2026-11-18T06:00:00Z')).toBe(Date.UTC(2026, 10, 18, 6));
    expect(parseTimeBucket(Date.UTC(2026, 10, 18, 6))).toBe(Date.UTC(2026, 10, 18, 6));
    for (const bad of [NaN, Infinity, 9e15, 'not a time', '', null, undefined, {}]) {
      expect(parseTimeBucket(bad)).toBeNull();
    }
  });

  it('an unusable bucket does not break the export', () => {
    const csv = timechartCsv(transformResults([...buckets, r({ time_bucket: Infinity, count: 1 }, 9)]));
    expect(csv.split('\n')).toHaveLength(3);
  });

  it('pivots a split-by into one column per series, empty where a bucket has none', () => {
    const lines = timechartCsv(transformResults(split)).split('\n');
    expect(lines[0]).toBe('time_bucket,bob,alice');
    expect(lines[1].split(',').slice(1)).toEqual(['5', '2']);
    expect(lines[2].split(',').slice(1)).toEqual(['0', '1']);
  });

  it('the Export button downloads it', () => {
    render(<TimechartView results={buckets} query="* | timechart span=6h count" />);
    fireEvent.click(screen.getByTitle('Export'));
    expect(dl.download).toHaveBeenCalledTimes(1);
    const [csv, filename] = dl.download.mock.calls[0];
    expect(csv).toBe(timechartCsv(transformResults(buckets)));
    expect(filename).toMatch(/^nano-export-timechart-.*\.csv$/);
  });
});

describe('top/rare CSV', () => {
  it('lists the values in ranked order with count and percent, formula-safe', () => {
    expect(rankedCsv(transform(top)).split('\n')).toEqual([
      'actor.user.name,count,percent',
      'judy.chen,6,60',
      `"'=HYPERLINK(""x"")",4,40`,
    ]);
  });

  it('the Export button downloads it, named for the view', () => {
    render(<RankedBarChart results={top} query="* | rare actor.user.name" />);
    fireEvent.click(screen.getByTitle('Export'));
    expect(dl.download).toHaveBeenCalledTimes(1);
    const [csv, filename] = dl.download.mock.calls[0];
    expect(csv).toBe(rankedCsv(transform(top)));
    expect(filename).toMatch(/^nano-export-rare-.*\.csv$/);
  });
});
