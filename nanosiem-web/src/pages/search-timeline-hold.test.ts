// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from 'vitest';
import { displayedHistogram, holdTimelineForRun, PENDING_TIMELINE, searchTimelineIdentity } from './search-timeline-hold';

const id = (query: string, prevalenceMax = 100) =>
  searchTimelineIdentity({ query, mode: 'piped', dataset: 'logs', prevalenceMax });
const chart = [
  { time: '2026-10-08T07:00:00Z', count: 120_000 },
  { time: '2026-10-08T07:01:00Z', count: 80_000 },
];

describe('searchTimelineIdentity (NAN-3273)', () => {
  it('ignores surrounding whitespace but not the query, mode, dataset or rarity filter', () => {
    expect(id(' metadata.log_source="apache_access" ')).toBe(id('metadata.log_source="apache_access"'));
    expect(id('a')).not.toBe(id('b'));
    expect(id('a', 10)).not.toBe(id('a'));
    expect(searchTimelineIdentity({ query: 'a', mode: 'sql', dataset: 'logs', prevalenceMax: 100 })).not.toBe(id('a'));
    expect(searchTimelineIdentity({ query: 'a', mode: 'piped', dataset: 'spans', prevalenceMax: 100 })).not.toBe(id('a'));
  });
});

describe('holdTimelineForRun (NAN-3273)', () => {
  it('holds the timeline on screen across a re-run of the same search (window roll)', () => {
    expect(holdTimelineForRun({ identity: id('a'), histogram: chart }, null, id('a')))
      .toEqual({ identity: id('a'), histogram: chart });
  });

  it('holds nothing for a different search', () => {
    expect(holdTimelineForRun({ identity: id('a'), histogram: chart }, null, id('b'))).toBeNull();
    expect(holdTimelineForRun({ identity: null, histogram: chart }, null, id('a'))).toBeNull();
  });

  it('carries a pending hold over back-to-back re-runs, but never an empty one', () => {
    const pending = { identity: id('a'), histogram: chart };
    expect(holdTimelineForRun({ identity: id('a'), histogram: PENDING_TIMELINE }, pending, id('a'))).toBe(pending);
    expect(holdTimelineForRun({ identity: id('a'), histogram: PENDING_TIMELINE }, null, id('a'))).toBeNull();
    expect(holdTimelineForRun({ identity: id('a'), histogram: PENDING_TIMELINE }, { identity: id('a'), histogram: [] }, id('a'))).toBeNull();
    expect(holdTimelineForRun({ identity: id('b'), histogram: PENDING_TIMELINE }, pending, id('b'))).toBeNull();
  });

  it('never resurrects an old hold once a read landed genuinely empty', () => {
    const stale = { identity: id('a'), histogram: chart };
    expect(holdTimelineForRun({ identity: id('a'), histogram: [] }, stale, id('a'))).toBeNull();
  });
});

describe('displayedHistogram (NAN-3273)', () => {
  it('shows the held timeline only while the run has not installed its own', () => {
    const hold = { identity: id('a'), histogram: chart };
    expect(displayedHistogram(PENDING_TIMELINE, hold)).toBe(chart);
    const landed = [{ time: '2026-10-08T07:02:00Z', count: 5 }];
    expect(displayedHistogram(landed, hold)).toBe(landed);
    // A read that landed empty is the window's answer: 0, not the held chart.
    const landedEmpty: typeof landed = [];
    expect(displayedHistogram(landedEmpty, hold)).toBe(landedEmpty);
    expect(displayedHistogram(PENDING_TIMELINE, null)).toBe(PENDING_TIMELINE);
  });
});
