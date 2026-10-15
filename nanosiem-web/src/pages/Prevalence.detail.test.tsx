// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
/**
 * NAN-3210 regression: on lean (enterprise-shared) tenants the artifact detail
 * answers 200 with empty facets and `availability.reason = 'warming'` until
 * product state publishes it. The expanded row rendered that as "No detail
 * data found" and never refetched, so every artifact looked empty.
 */
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { act, cleanup, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import type { ArtifactDetailResponse, ArtifactExplorerItem } from '@/lib/api/types';

const mocks = vi.hoisted(() => ({ detail: vi.fn() }));

vi.mock('@/lib/api', async importOriginal => {
  const original = await importOriginal<typeof import('@/lib/api')>();
  return { ...original, api: { ...original.api, getArtifactDetail: mocks.detail } };
});

import { DETAIL_WARMING_MAX_POLLS, DETAIL_WARMING_POLL_MS, detailWarmingDelay } from '@/lib/prevalence/detailWarming';
import { ExpandedArtifactDetail } from './Prevalence';

const artifact = {
  artifact: '10.1.3.149',
  artifact_type: 'ip_address_private',
  host_count: 3,
  host_count_saturated: false,
  total_occurrences: 6837,
  first_seen: '2026-10-07T00:00:00Z',
  last_seen: '2026-10-07T12:00:00Z',
  is_rare: false,
  prevalence_score: 0,
} as unknown as ArtifactExplorerItem;

const empty = (availability?: ArtifactDetailResponse['availability']): ArtifactDetailResponse => ({
  artifact: '10.1.3.149', artifact_type: 'ip_address_private',
  top_hosts: [], top_users: [], source_types: [], processes: [], top_file_names: [], network: [], geo: [], threat_intel: [],
  availability,
});

const warming = empty({ capability: 'prevalence', available: false, reason: 'warming', detail: 'Prevalence is being prepared after a restart; usually under 5 minutes' });
const ready: ArtifactDetailResponse = {
  ...empty({ capability: 'prevalence', available: true }),
  top_hosts: [{ host: 'ws-legal-066.corp.local', count: 6837, last_seen: '2026-10-07T12:00:00Z' }],
  source_types: [{ source_type: 'windows_sysmon', count: 6837 }],
};

function renderDetail(timeWindow = '1h') {
  return render(
    <MemoryRouter>
      <ExpandedArtifactDetail artifact={artifact} timeWindow={timeWindow} onDrilldown={() => {}} />
    </MemoryRouter>,
  );
}

async function flush() {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
}

beforeEach(() => {
  vi.useFakeTimers();
  mocks.detail.mockReset();
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

it('shows warming instead of "no data" and polls until the detail is published', async () => {
  mocks.detail.mockResolvedValueOnce(warming).mockResolvedValueOnce(warming).mockResolvedValue(ready);
  renderDetail();
  await flush();
  expect(screen.getByText('Building detail…')).toBeTruthy();
  expect(screen.queryByText(/No detail data found/)).toBeNull();

  await act(async () => { await vi.advanceTimersByTimeAsync(DETAIL_WARMING_POLL_MS); });
  await flush();
  expect(screen.getByText('Building detail…')).toBeTruthy();

  await act(async () => { await vi.advanceTimersByTimeAsync(detailWarmingDelay(1)); });
  await flush();
  expect(mocks.detail).toHaveBeenCalledTimes(3);
  expect(mocks.detail).toHaveBeenCalledWith('10.1.3.149', '1h', expect.any(AbortSignal));
  expect(screen.getByText('ws-legal-066.corp.local')).toBeTruthy();
  expect(screen.queryByText('Building detail…')).toBeNull();
});

it('stops polling at its bound', async () => {
  mocks.detail.mockResolvedValue(warming);
  renderDetail();
  await flush();
  for (let i = 0; i < DETAIL_WARMING_MAX_POLLS + 5; i++) {
    await act(async () => { await vi.advanceTimersByTimeAsync(detailWarmingDelay(i)); });
    await flush();
  }
  expect(mocks.detail).toHaveBeenCalledTimes(DETAIL_WARMING_MAX_POLLS + 1);
  expect(screen.getByText(/still being prepared/)).toBeTruthy();
});

it('surfaces a read failure instead of "no data"', async () => {
  mocks.detail.mockResolvedValue(empty({ capability: 'prevalence', available: false, reason: 'read_failed', detail: 'Prevalence could not be read: boom' }));
  renderDetail();
  await flush();
  expect(screen.getByText('Prevalence could not be read: boom')).toBeTruthy();
  expect(screen.queryByText(/No detail data found/)).toBeNull();
  await act(async () => { await vi.advanceTimersByTimeAsync(DETAIL_WARMING_POLL_MS * 3); });
  expect(mocks.detail).toHaveBeenCalledTimes(1);
});


it('aborts the active detail request and stops polling on navigation', async () => {
  mocks.detail.mockImplementation((_artifact, _window, signal) => new Promise((_resolve, reject) => {
    signal.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')));
  }));
  const view = renderDetail();
  await flush();
  const signal = mocks.detail.mock.calls[0][2] as AbortSignal;
  expect(signal.aborted).toBe(false);
  view.unmount();
  expect(signal.aborted).toBe(true);
  await act(async () => { await vi.advanceTimersByTimeAsync(60_000); });
  expect(mocks.detail).toHaveBeenCalledTimes(1);
});

/** NAN-3766: a common artifact's detail covers only the newest slice of a 7d window. */
const coverage = (scannedStart: string, refining: boolean, complete = false) => ({
  complete, approximate: false, refining,
  scanned_start: scannedStart, scanned_end: '2026-10-13T15:00:00.000000Z',
  window_start: '2026-10-06T15:00:00.000000Z', window_end: '2026-10-13T15:00:00.000000Z',
});

it('labels a partial detail honestly and polls while a wider answer is refining', async () => {
  const first = { ...ready, coverage: coverage('2026-10-13T09:00:00.000000Z', true) };
  const wider = { ...ready, top_hosts: [{ host: 'ws-legal-066.corp.local', count: 90210, last_seen: '2026-10-13T15:00:00Z' }],
    coverage: coverage('2026-10-11T10:30:00.000000Z', false) };
  mocks.detail.mockResolvedValueOnce(first).mockResolvedValue(wider);
  renderDetail('7d');
  await flush();
  // The newest-slice facets render at once, never as if they were the whole window.
  expect(screen.getByText('ws-legal-066.corp.local')).toBeTruthy();
  const label = screen.getByTestId('detail-coverage');
  expect(label.textContent).toBe('partial · last 6h of 7d · refining…');
  expect(label.className).toContain('font-mono');
  expect(label.className).toContain('text-[10.5px]');
  expect(label.getAttribute('title')).toContain('the newest 6h of this 7d window. Counts cover only that range.');

  await act(async () => { await vi.advanceTimersByTimeAsync(DETAIL_WARMING_POLL_MS); });
  await flush();
  expect(mocks.detail).toHaveBeenCalledTimes(2);
  expect(screen.getByText('90,210')).toBeTruthy();
  expect(screen.getByTestId('detail-coverage').textContent).toBe('partial · last 2d 4h of 7d');
  expect(screen.queryByText('Loading context…')).toBeNull();

  // A final partial answer stops polling but keeps its disclosure.
  await act(async () => { await vi.advanceTimersByTimeAsync(60_000); });
  expect(mocks.detail).toHaveBeenCalledTimes(2);
  expect(screen.getByTestId('detail-coverage')).toBeTruthy();
});

it('shows no coverage label when the whole window was counted', async () => {
  mocks.detail.mockResolvedValue({ ...ready, coverage: coverage('2026-10-06T15:00:00.000000Z', false, true) });
  renderDetail('7d');
  await flush();
  expect(screen.getByText('ws-legal-066.corp.local')).toBeTruthy();
  expect(screen.queryByTestId('detail-coverage')).toBeNull();
  await act(async () => { await vi.advanceTimersByTimeAsync(60_000); });
  expect(mocks.detail).toHaveBeenCalledTimes(1);
});
