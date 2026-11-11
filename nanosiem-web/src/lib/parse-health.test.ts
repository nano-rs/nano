// SPDX-License-Identifier: AGPL-3.0-or-later
/** NAN-5264: fallback parses warn on the source instead of reading as healthy. */
import { describe, expect, it } from 'vitest';
import { FALLBACK_WARN_RATE, fallbackRate, fallbackWarns, formatShare } from './parse-health';

describe('fallback warning', () => {
  it('warns on the reported case: 16 of 17 events fell back', () => {
    const health = { parse_attempts_24h: 17, parse_fallbacks_24h: 16, parse_fallback_rate_24h: 16 / 17 };
    expect(fallbackWarns(health)).toBe(true);
    expect(formatShare(fallbackRate(health)!)).toBe('94.12%');
  });

  it('stays quiet at or below the threshold and with no traffic', () => {
    expect(fallbackWarns({ parse_attempts_24h: 1000, parse_fallbacks_24h: 20, parse_fallback_rate_24h: 0.02 })).toBe(false);
    expect(fallbackWarns({ parse_attempts_24h: 1000, parse_fallbacks_24h: 0, parse_fallback_rate_24h: 0 })).toBe(false);
    expect(fallbackWarns({ parse_attempts_24h: 0, parse_fallback_rate_24h: null })).toBe(false);
    expect(fallbackWarns(null)).toBe(false);
    expect(FALLBACK_WARN_RATE).toBeLessThan(0.05);
  });

  it('derives the rate from counts when an older API omits it', () => {
    expect(fallbackRate({ parse_attempts_24h: 10, parse_fallbacks_24h: 5 })).toBe(0.5);
    expect(fallbackRate({ parse_attempts_24h: 0 })).toBeNull();
  });

  it('never prints a non-zero share as zero', () => {
    expect(formatShare(0.00001)).toBe('<0.01%');
    expect(formatShare(0)).toBe('0.00%');
  });
});
