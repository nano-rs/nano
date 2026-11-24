// SPDX-License-Identifier: AGPL-3.0-or-later
// NAN-5842: the Impact & baseline card buckets the sparse /api/rules/stats
// rows into contiguous, zero-filled UTC days.
import { describe, expect, it } from 'vitest';
import { dailyBuckets } from './helpers';

const NOW = new Date('2026-11-22T03:00:00Z');

describe('dailyBuckets (NAN-5842)', () => {
  it('zero-fills a window of UTC days ending today', () => {
    const b = dailyBuckets([{ date: '2026-11-22', match_count: 1 }], 7, NOW);
    expect(b.map((d) => d.date)).toEqual([
      '2026-11-16', '2026-11-17', '2026-11-18', '2026-11-19', '2026-11-20', '2026-11-21', '2026-11-22',
    ]);
    expect(b.map((d) => d.count)).toEqual([0, 0, 0, 0, 0, 0, 1]);
  });

  it('a rule that never fired gets an all-zero window, not an empty one', () => {
    expect(dailyBuckets([], 7, NOW).map((d) => d.count)).toEqual([0, 0, 0, 0, 0, 0, 0]);
    expect(dailyBuckets(undefined, 3, NOW)).toHaveLength(3);
  });

  it('sparse active days land on their own dates: the last 7 days are calendar days', () => {
    const stats = [
      { date: '2026-11-01', match_count: 50 }, // outside 14d
      { date: '2026-11-10', match_count: 6 },
      { date: '2026-11-14', match_count: 2 },
      { date: '2026-11-18', match_count: 2 },
      { date: '2026-11-22', match_count: 3 },
    ];
    const days = dailyBuckets(stats, 14, NOW);
    const sum = (xs: { count: number }[]) => xs.reduce((a, d) => a + d.count, 0);
    expect(sum(days.slice(-7))).toBe(5); // 11-16..11-22
    expect(sum(days.slice(0, 7))).toBe(8); // 11-09..11-15
  });

  it('tolerates timestamp-shaped dates and null counts', () => {
    const b = dailyBuckets([{ date: '2026-11-21T00:00:00Z', match_count: null }, { date: '2026-11-21', match_count: 4 }], 2, NOW);
    expect(b).toEqual([{ date: '2026-11-21', count: 4 }, { date: '2026-11-22', count: 0 }]);
  });
});
