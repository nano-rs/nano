// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from 'vitest';
import { retryAfterSeconds, runParserTests } from './parser-test-pool';

const busy = (retryAfter?: number) => Object.assign(new Error('busy'), { status: 429, retryAfter });

describe('runParserTests', () => {
  it('keeps at most `limit` requests in flight and preserves order', async () => {
    let inFlight = 0;
    let peak = 0;
    const out = await runParserTests(
      Array.from({ length: 20 }, (_, i) => i),
      async (i) => {
        inFlight++;
        peak = Math.max(peak, inFlight);
        await new Promise((r) => setTimeout(r, 1));
        inFlight--;
        return i * 2;
      },
      { limit: 4 },
    );
    expect(peak).toBeLessThanOrEqual(4);
    expect(out).toEqual(Array.from({ length: 20 }, (_, i) => i * 2));
  });

  it('retries a 429 after Retry-After, then succeeds', async () => {
    const waits: number[] = [];
    let calls = 0;
    const out = await runParserTests(
      ['a'],
      async (x) => {
        calls++;
        if (calls < 3) throw busy(2);
        return x;
      },
      { sleep: async (ms) => void waits.push(ms) },
    );
    expect(out).toEqual(['a']);
    expect(waits).toEqual([2000, 2000]);
  });

  it('does not retry other errors, and gives up after bounded 429 retries', async () => {
    await expect(
      runParserTests(['a'], async () => { throw Object.assign(new Error('bad'), { status: 400 }); }, { sleep: async () => {} }),
    ).rejects.toThrow('bad');
    let calls = 0;
    await expect(
      runParserTests(['a'], async () => { calls++; throw busy(1); }, { sleep: async () => {} }),
    ).rejects.toThrow('busy');
    expect(calls).toBe(6);
  });

  it('reads Retry-After only from a 429, with a default and a cap', () => {
    expect(retryAfterSeconds(busy(3))).toBe(3);
    expect(retryAfterSeconds(busy())).toBe(1);
    expect(retryAfterSeconds(busy(600))).toBe(10);
    expect(retryAfterSeconds(Object.assign(new Error('x'), { status: 503, retryAfter: 3 }))).toBeUndefined();
  });
});
