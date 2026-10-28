// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
import { act, cleanup, renderHook, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';

const completeStep = vi.hoisted(() => vi.fn());
vi.mock('@/lib/api', () => ({ api: { onboarding: { completeStep } } }));
vi.mock('@/lib/auth-token', () => ({ getAccessToken: () => null }));
vi.mock('@/lib/request-credentials', () => ({ requestCredentials: () => 'same-origin' }));
vi.mock('@/lib/query-autocomplete', () => ({ invalidateFieldUsageCache: vi.fn() }));

import { useSearchHistory } from './useSearchHistory';

const query = {
  query: 'private query text', queryMode: 'piped' as const,
  timeRange: { type: 'preset' as const, preset: 'Last 24 hours' },
};
beforeEach(() => {
  completeStep.mockReset().mockResolvedValue({});
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
    ok: true,
    json: async () => ({ entries: [], history_enabled: false }),
  }));
});
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

test('history disabled: a run completes First Search without persisting query details', async () => {
  const { result } = renderHook(() => useSearchHistory());
  await waitFor(() => expect(result.current.isLoading).toBe(false));
  expect(completeStep).not.toHaveBeenCalled();
  await act(async () => {
    await Promise.all([result.current.addToSearchHistory(query), result.current.addToSearchHistory(query)]);
  });
  expect(completeStep).toHaveBeenCalledExactlyOnceWith({ step: 'first_searches' });
  expect(fetch).toHaveBeenCalledTimes(1); // initial GET only, no history POST
  expect(result.current.searchHistory).toEqual([]);
});

test('a disabled search surface does not record onboarding completion', async () => {
  const { result } = renderHook(() => useSearchHistory({ enabled: false }));
  await act(async () => { await result.current.addToSearchHistory(query); });
  expect(fetch).not.toHaveBeenCalled();
  expect(completeStep).not.toHaveBeenCalled();
});

test('a failed completion does not reject the search and retries on the next run', async () => {
  completeStep.mockRejectedValueOnce(new Error('unavailable'));
  const { result } = renderHook(() => useSearchHistory());
  await waitFor(() => expect(result.current.isLoading).toBe(false));
  await act(async () => { await result.current.addToSearchHistory(query); });
  await act(async () => { await result.current.addToSearchHistory(query); });
  expect(completeStep).toHaveBeenCalledTimes(2);
});

test('a first run racing the history-settings GET still completes when history rejects it', async () => {
  let finishSettings!: (response: Response) => void;
  vi.mocked(fetch).mockReset()
    .mockImplementationOnce(() => new Promise<Response>((resolve) => { finishSettings = resolve; }))
    .mockResolvedValueOnce({ ok: false, status: 400 } as Response);
  const { result } = renderHook(() => useSearchHistory());
  await act(async () => { await result.current.addToSearchHistory(query); });
  expect(completeStep).toHaveBeenCalledExactlyOnceWith({ step: 'first_searches' });
  await act(async () => {
    finishSettings({ ok: true, json: async () => ({ entries: [], history_enabled: false }) } as Response);
  });
  expect(result.current.searchHistory).toEqual([]);
});
