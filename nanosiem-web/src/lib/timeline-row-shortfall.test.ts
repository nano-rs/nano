import { describe, it, expect } from 'vitest';
import { shouldWarnRowShortfall } from './timeline-row-shortfall';

describe('shouldWarnRowShortfall (NAN-5328)', () => {
  it('never warns for an aggregate query', () => {
    expect(shouldWarnRowShortfall({ eventCount: 5000, resultCount: 11, isAggregate: true })).toBe(false);
  });
  it('warns when a raw-event fetch returned fewer rows than the stream counted', () => {
    expect(shouldWarnRowShortfall({ eventCount: 5000, resultCount: 1000, isAggregate: false })).toBe(true);
  });
  it('does not warn when counts match or are unknown', () => {
    expect(shouldWarnRowShortfall({ eventCount: 5000, resultCount: 5000 })).toBe(false);
    expect(shouldWarnRowShortfall({ eventCount: 5000 })).toBe(false);
    expect(shouldWarnRowShortfall({ eventCount: 0, resultCount: 0 })).toBe(false);
  });
});
