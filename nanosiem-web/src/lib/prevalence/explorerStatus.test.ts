import { describe, expect, it } from 'vitest';
import { explorerStatusLabel } from './explorerStatus';

describe('explorer snapshot status', () => {
  it('distinguishes warming from a definitive empty result', () => {
    expect(explorerStatusLabel({ warming: true, retry_after_s: 600 })).toContain('10 min');
    expect(explorerStatusLabel({ warming: true, retry_after_s: 61 })).toContain('2 min');
    expect(explorerStatusLabel({ warming: true })).toContain('waiting');
    expect(explorerStatusLabel({ warming: true, retry_after_s: NaN })).toContain('waiting');
    expect(explorerStatusLabel({ stale: false, warming: false })).toBeNull();
    expect(explorerStatusLabel(undefined)).toBeNull();
  });

  it('labels stale results even when the page has artifacts', () => {
    expect(explorerStatusLabel({ stale: true })).toContain('older snapshot');
    expect(explorerStatusLabel({ stale: true, warming: true })).toContain('Warming up');
  });
});
