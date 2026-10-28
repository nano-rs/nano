// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
import { act, renderHook } from '@testing-library/react';
import { afterEach, expect, test, vi } from 'vitest';
import { useRefetchOnFocus, REFETCH_ON_FOCUS_MIN_INTERVAL_MS } from './use-refetch-on-focus';

afterEach(() => vi.useRealTimers());

test('refetches on focus and visibility, collapsing bursts, and stops after unmount', () => {
  vi.useFakeTimers();
  vi.setSystemTime(10_000_000);
  const refetch = vi.fn();
  const { unmount } = renderHook(() => useRefetchOnFocus(refetch));
  window.dispatchEvent(new Event('focus'));
  document.dispatchEvent(new Event('visibilitychange'));
  expect(refetch).toHaveBeenCalledTimes(1);
  vi.setSystemTime(10_000_000 + REFETCH_ON_FOCUS_MIN_INTERVAL_MS + 1);
  document.dispatchEvent(new Event('visibilitychange'));
  expect(refetch).toHaveBeenCalledTimes(2);
  unmount();
  vi.setSystemTime(20_000_000);
  window.dispatchEvent(new Event('focus'));
  expect(refetch).toHaveBeenCalledTimes(2);
});

test('does nothing when disabled', () => {
  const refetch = vi.fn();
  renderHook(() => useRefetchOnFocus(refetch, false));
  window.dispatchEvent(new Event('focus'));
  expect(refetch).not.toHaveBeenCalled();
});

test('refreshes a quick return after a completion inside the cooldown', () => {
  vi.useFakeTimers();
  vi.setSystemTime(10_000_000);
  let completed = false;
  const observed: boolean[] = [];
  const { unmount } = renderHook(() => useRefetchOnFocus(() => observed.push(completed)));
  window.dispatchEvent(new Event('focus'));
  completed = true;
  act(() => {
    vi.advanceTimersByTime(100);
    window.dispatchEvent(new Event('focus'));
    vi.advanceTimersByTime(REFETCH_ON_FOCUS_MIN_INTERVAL_MS);
  });
  expect(observed).toEqual([false, true]);
  window.dispatchEvent(new Event('focus'));
  unmount();
  vi.advanceTimersByTime(REFETCH_ON_FOCUS_MIN_INTERVAL_MS);
  expect(observed).toEqual([false, true]);
});
