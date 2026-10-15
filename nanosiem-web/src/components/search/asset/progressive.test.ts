// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it, vi } from 'vitest';
import { fetchProgressive, progressLabel, rarityWaitLabel } from './progressive';

describe('fetchProgressive (NAN-3094)', () => {
  it('renders each partial answer and polls without the bypass until complete', async () => {
    vi.useFakeTimers();
    const answers = [
      { n: 1, progress: { complete: false, retry_after_ms: 10 } },
      { n: 2, progress: { complete: false, retry_after_ms: 10 } },
      { n: 3, progress: { complete: true } },
    ];
    const bypasses: boolean[] = [];
    const seen: number[] = [];
    const done = fetchProgressive(
      async (bypass) => { bypasses.push(bypass); return answers[bypasses.length - 1]; },
      (response) => seen.push(response.n),
      () => true,
      true,
    );
    await vi.runAllTimersAsync();
    const last = await done;
    vi.useRealTimers();
    expect(last.n).toBe(3);
    expect(seen).toEqual([1, 2, 3]);
    expect(bypasses).toEqual([true, false, false]);
  });

  it('stops polling once the view is stale', async () => {
    let current = true;
    const calls = vi.fn(async () => ({ progress: { complete: false, retry_after_ms: 1 } }));
    const done = fetchProgressive(calls, () => { current = false; }, () => current);
    await done;
    expect(calls).toHaveBeenCalledTimes(1);
  });

  it('a response without progress is final', async () => {
    const calls = vi.fn(async () => ({ value: 1, progress: undefined }));
    await fetchProgressive(calls, () => undefined, () => true);
    expect(calls).toHaveBeenCalledTimes(1);
  });

  it('labels an incomplete view with its coverage', () => {
    expect(progressLabel({ complete: false, covered_start: '2026-09-30T12:04:31.000000Z' })).toBe(
      'refining · covers since 12:04:31Z',
    );
    // NAN-3252: full coverage is "refining", not loading.
    expect(progressLabel(
      { complete: false, covered_start: '2026-09-30T12:00:00.000000Z' },
      '2026-09-30T12:00:00Z',
    )).toBe('refining…');
    expect(progressLabel(
      { complete: false, covered_start: '2026-09-30T12:04:31.000000Z' },
      '2026-09-30T12:00:00Z',
    )).toBe('refining · covers since 12:04:31Z');
    expect(progressLabel({ complete: false })).toBe('reading events…');
    expect(progressLabel({ complete: true })).toBeNull();
    expect(progressLabel({ complete: true, note: 'covers the newest 24 h' })).toBe('covers the newest 24 h');
  });
});

it('aborts the progressive delay without another request or stale update', async () => {
  vi.useFakeTimers();
  const controller = new AbortController();
  const calls = vi.fn(async () => ({ progress: { complete: false } }));
  const updates = vi.fn(() => controller.abort());
  await expect(fetchProgressive(calls, updates, () => true, false, controller.signal)).rejects.toMatchObject({ name: 'AbortError' });
  expect(calls).toHaveBeenCalledTimes(1);
  expect(vi.getTimerCount()).toBe(0);
  vi.useRealTimers();
});

it('names what Rarity waits on instead of a bare spinner (NAN-3252)', () => {
  expect(rarityWaitLabel({ complete: false })).toBe('reading events…');
  expect(rarityWaitLabel({ complete: false, covered_start: '2026-09-30T12:00:00Z' })).toBe('refining host counts…');
  expect(rarityWaitLabel({ complete: true })).toBeNull();
  expect(rarityWaitLabel(null)).toBeNull();
});
