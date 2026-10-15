// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it, vi } from 'vitest';
import { EventPayloadCache, eventPayloadKey } from './event-payload-cache';

describe('Asset payload cache', () => {
  it('coalesces prefetch and expansion and reuses reopened events', async () => {
    const cache = new EventPayloadCache();
    const fetcher = vi.fn(async () => ({ id: 'one', ext: 'full' }));
    const prefetch = cache.load('one', fetcher);
    expect(cache.load('one', fetcher)).toBe(prefetch);
    await prefetch;
    await cache.load('one', fetcher);
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
  it('retains stale fields during refresh and on failure', async () => {
    vi.useFakeTimers();
    const cache = new EventPayloadCache(1024, 10);
    await cache.load('one', async () => ({ value: 'old' }));
    vi.advanceTimersByTime(11);
    const refresh = cache.load('one', async () => { throw new Error('offline'); });
    expect(cache.peek('one')).toEqual({ value: 'old' });
    await expect(refresh).rejects.toThrow('offline');
    expect(cache.peek('one')).toEqual({ value: 'old' });
    await cache.load('one', async () => ({ value: 'new' }));
    expect(cache.peek('one')).toEqual({ value: 'new' });
    vi.useRealTimers();
  });
  it('bounds resident bytes and excludes oversized payloads', async () => {
    const cache = new EventPayloadCache(40);
    await cache.load('one', async () => ({ value: '123' }));
    await cache.load('two', async () => ({ value: '456' }));
    expect(cache.peek('one')).toBeNull();
    expect(cache.peek('two')).toEqual({ value: '456' });
    await cache.load('large', async () => ({ value: 'x'.repeat(100) }));
    expect(cache.peek('large')).toBeNull();
  });
  it('aborts owned work and discards late answers on scope reset', async () => {
    const cache = new EventPayloadCache();
    let signal!: AbortSignal;
    let finish!: (value: Record<string, unknown>) => void;
    const request = cache.load('one', (captured) => {
      signal = captured;
      return new Promise((resolve) => { finish = resolve; });
    });
    cache.dispose();
    expect(signal.aborted).toBe(true);
    finish({ private: 'old tenant' });
    await request;
    expect(cache.peek('one')).toBeNull();
    await expect(cache.load('one', async () => ({}))).rejects.toMatchObject({ name: 'AbortError' });
  });
  it('does not cache misses and isolates timestamp/source identity', async () => {
    const cache = new EventPayloadCache();
    const lookup = vi.fn(async () => null);
    await cache.load('one', lookup);
    await cache.load('one', lookup);
    expect(lookup).toHaveBeenCalledTimes(2);
    expect(eventPayloadKey('id', 't1', 's1')).not.toBe(eventPayloadKey('id', 't2', 's1'));
    expect(eventPayloadKey('id', 't1', 's1')).not.toBe(eventPayloadKey('id', 't1', 's2'));
  });
});
