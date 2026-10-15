// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AssetStream } from './AssetStream';
import type { AssetEventsRequest } from '@/lib/api/types';

const mocks = vi.hoisted(() => ({ events: vi.fn() }));
vi.mock('@/lib/api', () => ({ api: {
  fetchLog: vi.fn(), getAssetEvents: mocks.events,
  getSchemaFields: async () => ({ schema: 'udm', fields: [] }),
} }));

// NAN-3291: a busy asset over a 6 h window: far more events than the lean
// snapshot holds, counted exactly by the full-window aggregates.
const TOTAL = 330_000;
const props = {
  identifierField: 'device.hostname', identifierValue: 'ws-it-083.corp.local', identities: [],
  timeRange: { start: '2026-10-08T04:53:27Z', end: '2026-10-08T10:53:27Z' },
};
const page = (offset: number, count: number) => Array.from({ length: count }, (_, index) => ({
  id: `e-${offset + index}`, timestamp: '2026-10-08T10:50:00Z', source_type: 'windows_sysmon',
  event_kind: 'PROCESS', summary: { message: `event ${offset + index}` },
}));

function view() {
  return render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
    <AssetStream {...props} />
  </QueryClientProvider>);
}

beforeEach(() => {
  mocks.events.mockReset().mockImplementation(async (req: AssetEventsRequest) => {
    if (req.fetch === 'summary') {
      return {
        events: [], total_count: TOTAL, total_count_exact: true, has_more: true, offset: 0, limit: 1,
        facets: { event_kind: [['PROCESS', 300_000]], source_type: [['windows_sysmon', TOTAL]], user: [] },
        progress: { complete: true, covered_start: '2026-10-08T04:53:27.000000Z', covered_end: '2026-10-08T10:53:27.000000Z' },
      };
    }
    const offset = req.cursor ? 50 : (req.offset ?? 0);
    return {
      events: page(offset, 50), total_count: offset + 51, total_count_exact: false, has_more: true,
      offset, limit: 50, facets: {}, next_cursor: { time: '2026-10-08T10:49:00Z', uid: `c-${offset}` },
    };
  });
});
afterEach(cleanup);

it('shows exact full-window counts from the summary and keeps paging by cursor', async () => {
  view();
  const strip = await screen.findByTestId('asset-stream-counts');
  expect(strip.textContent).toBe('counts exact · full window · all sources for this asset');
  expect(strip.textContent).not.toMatch(/SQL|validation|lower bound|limited to/i);
  await screen.findByText(`(50 of ${TOTAL.toLocaleString()} loaded)`);

  // has_more follows the exact total: 50 of 330,000 means more pages.
  fireEvent.click(await screen.findByRole('button', { name: /Load 50 more/ }));
  await screen.findByText(`(100 of ${TOTAL.toLocaleString()} loaded)`);
  const pages = mocks.events.mock.calls.map(([req]) => req as AssetEventsRequest).filter((req) => req.fetch === 'page');
  expect(pages).toHaveLength(2);
  expect(pages[1].cursor).toEqual({ time: '2026-10-08T10:49:00Z', uid: 'c-0' });
  expect(pages[1].offset).toBe(50);
  // The exact total survives the page merge; the button stays for more.
  expect(screen.getByRole('button', { name: /Load 50 more/ })).toBeTruthy();
  const summaries = mocks.events.mock.calls.filter(([req]) => (req as AssetEventsRequest).fetch === 'summary');
  expect(summaries).toHaveLength(1);
});

it('polls an incomplete summary and labels it as refining, never as a lower-bound error', async () => {
  let polls = 0;
  mocks.events.mockImplementation(async (req: AssetEventsRequest) => {
    if (req.fetch === 'summary') {
      polls += 1;
      return polls === 1
        ? { events: [], total_count: 0, total_count_exact: false, has_more: false, offset: 0, limit: 1, facets: {},
          progress: { complete: false, retry_after_ms: 1 } }
        : { events: [], total_count: 120, total_count_exact: true, has_more: true, offset: 0, limit: 1, facets: {},
          progress: { complete: true } };
    }
    return { events: page(0, 50), total_count: 51, total_count_exact: false, has_more: true, offset: 0, limit: 50, facets: {} };
  });
  view();
  await waitFor(() => expect(polls).toBe(2));
  await screen.findByText('(50 of 120 loaded)');
  expect(screen.getByTestId('asset-stream-counts').textContent).toContain('counts exact');
});

it('renders a plain-language snapshot note with local times', async () => {
  mocks.events.mockImplementation(async (req: AssetEventsRequest) => req.fetch === 'summary'
    ? { events: [], total_count: 50_000, total_count_exact: false, has_more: false, offset: 0, limit: 1, facets: {},
      progress: { complete: true, note: 'Showing detail from the newest 50,000 events (since 2026-10-08T10:50:00Z); counts cover the full window' } }
    : { events: page(0, 50), total_count: 51, total_count_exact: false, has_more: true, offset: 0, limit: 50, facets: {} });
  view();
  const strip = await screen.findByTestId('asset-stream-counts');
  expect(strip.textContent).toMatch(/^counts Showing detail from the newest 50,000 events \(since \d{2}:\d{2}\); counts cover the full window$/);
  expect(strip.textContent).not.toContain('2026-10-08T');
});
