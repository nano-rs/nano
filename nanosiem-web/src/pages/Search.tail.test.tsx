// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
// G6 port (NAN-4927): live tail on the ClickHouse search path.
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Search } from './Search';

const mocks = vi.hoisted(() => ({
  stream: vi.fn(), async: vi.fn(), fields: vi.fn(), legacy: vi.fn(),
  cancel: vi.fn().mockResolvedValue({}), cancelJob: vi.fn().mockResolvedValue({}),
  noop: vi.fn(), mutation: vi.fn().mockResolvedValue({}), history: vi.fn(),
}));
vi.mock('@/lib/api', () => ({
  ApiClientError: class extends Error {},
  api: {
    searchStreamSSE: mocks.stream, searchAsync: mocks.async,
    cancelSearch: mocks.cancel, cancelSearchJob: mocks.cancelJob,
    getExtFieldNames: async () => [], getSchemaFields: async () => ({ schema: 'udm', fields: [] }),
    listSearchJobs: async () => [],
  },
}));
vi.mock('@/hooks/use-api', async importOriginal => {
  const original = await importOriginal<typeof import('@/hooks/use-api')>();
  const hooks = Object.fromEntries(Object.keys(original).filter(key => key.startsWith('use')).map(key => [key, () => ({
    mutate: mocks.mutation, data: undefined, loading: false, refetch: mocks.noop,
  })]));
  // useSearch binds a fresh mutate each render in production, so handleSearch
  // (and the URL-sync effect that depends on it) changes identity every render.
  return { ...original, ...hooks, useSearch: () => ({ mutate: (...args: unknown[]) => mocks.legacy(...args) }), useFieldStats: () => ({ mutate: mocks.fields }) };
});
vi.mock('@/hooks/use-capabilities', async importOriginal => ({ ...(await importOriginal<object>()), useCapabilities: () => ({ capabilities: {} }) }));
vi.mock('@/contexts/AuthContext', () => ({ useAuth: () => ({ user: {}, hasPermission: () => true, isAuthenticated: true }) }));
vi.mock('@/contexts/UserPreferencesContext', () => ({ useUserPreferences: () => ({ defaultTimeRange: '1h', queryMode: 'piped' }) }));
vi.mock('@/contexts/PageContext', () => ({ useHereCardOverride: () => {} }));
vi.mock('@/enterprise/contexts/NotebookContext', () => ({ useNotebookCapture: () => ({ captureSearch: mocks.noop }) }));
vi.mock('@/enterprise/hooks/use-melod-job', () => ({ useMelodJob: () => ({ loading: false }) }));
vi.mock('@/hooks/useSearchHistory', () => ({ useSearchHistory: () => ({ searchHistory: [], addToSearchHistory: mocks.history, refreshHistory: mocks.noop }) }));
vi.mock('@/hooks/use-mobile', () => ({ useIsMobile: () => false }));
vi.mock('@/components/reports/ScheduleReportDialog', () => ({ ScheduleReportDialog: () => null }));
vi.mock('@/components/dashboard', () => ({ AddToDashboardDialog: () => null }));
vi.mock('@/components/DemoHints', () => ({ SearchDemoHint: () => null }));
vi.mock('@/components/search', async importOriginal => ({
  ...(await importOriginal<object>()),
  SearchResults: ({ results, totalCount }: { results: Array<{ fields: Record<string, unknown> }>; totalCount: number }) => (
    <output data-testid="rows" data-total={totalCount}>{results.map(r => String(r.fields.id)).join(',')}</output>
  ),
}));
(globalThis as unknown as { ResizeObserver: unknown }).ResizeObserver ??= class { observe() {} unobserve() {} disconnect() {} };

beforeEach(() => {
  vi.clearAllMocks();
  localStorage.clear();
  sessionStorage.clear();
  mocks.fields.mockResolvedValue({ fields: [] });
  // The SSE transport is unavailable → the page falls back to the async
  // endpoint, which answers synchronously with rows.
  mocks.stream.mockImplementation((_request, callbacks) => {
    queueMicrotask(() => callbacks.onError?.({ code: 'NETWORK_ERROR', message: 'no sse' }));
    return new AbortController();
  });
  mocks.async.mockImplementation(async () => ({
    results: [
      { id: 'e2', timestamp: new Date(Date.now() - 20_000).toISOString(), message: 'two' },
      { id: 'e1', timestamp: new Date(Date.now() - 40_000).toISOString(), message: 'one' },
    ],
    total_count: 2, fields: [], execution_time_ms: 1, display_type: 'events',
    histogram: [
      { time: new Date(Date.now() - 60_000).toISOString(), count: 1 },
      { time: new Date(Date.now() - 30_000).toISOString(), count: 1 },
    ],
  }));
});
afterEach(cleanup);



// NAN-2551 / NAN-3254: a tail tick prepends the arrivals instead of
// rebuilding the search, dedupes the deliberate window overlap on the event
// id, and the displayed total advances with the arrivals.
it('live tail prepends new events without re-running the search', async () => {
  // The source as ClickHouse holds it. `late` rows were ingested after the
  // search ran: e3 is a genuine new event, eLate a late insert with an old
  // event time. e0 is old and was already counted, just below the loaded page.
  const at = Date.now();
  const source = [
    { id: 'e3', ms: at, late: true },
    { id: 'eLate', ms: at - 25_000, late: true },
    { id: 'e2', ms: at - 20_000, late: false },
    { id: 'e1', ms: at - 40_000, late: false },
    { id: 'e0', ms: at - 90_000, late: false },
  ];
  mocks.legacy.mockImplementation(async (req: { query: string; time_range: { start: string; end: string }; limit: number; offset: number }) => {
    const startMs = Date.parse(req.time_range.start);
    const endMs = Date.parse(req.time_range.end);
    const rows = source
      .filter(r => r.ms >= startMs && r.ms <= endMs)
      .filter(r => !req.query.includes('_inserted_at') || !r.late)
      .slice(req.offset ?? 0, (req.offset ?? 0) + req.limit)
      .map(r => ({ id: r.id, timestamp: new Date(r.ms).toISOString(), message: r.id }));
    return { results: rows, total_count: rows.length, fields: [], execution_time_ms: 1 };
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/search#q=error&time=Last+15+minutes&run=true']}><Search /></MemoryRouter>
    </QueryClientProvider>,
  );
  await waitFor(() => expect(screen.getByTestId('rows').textContent).toBe('e2,e1'));
  const streamsBefore = mocks.stream.mock.calls.length;
  const asyncBefore = mocks.async.mock.calls.length;
  vi.useFakeTimers({ shouldAdvanceTime: true });
  try {
    fireEvent.click(screen.getByText('tail -f'));
    await act(async () => { await vi.advanceTimersByTimeAsync(15_500); });
    // e3 and the late insert arrive; e0 (already counted) is never re-counted.
    await waitFor(() => expect(screen.getByTestId('rows').textContent).toBe('e3,eLate,e2,e1'));
    expect(screen.getByTestId('rows').getAttribute('data-total')).toBe('4');
    // The arming read seeded only rows ingested before the search ran.
    expect(mocks.legacy.mock.calls.some(call => (call[0] as { query: string }).query.includes('| where _inserted_at <= "'))).toBe(true);
    // The poll is a lean read: no histogram companion, no field stats.
    const poll = mocks.legacy.mock.calls.find(call => (call[0] as { skip_histogram?: boolean; query: string }).skip_histogram && !(call[0] as { query: string }).query.includes('_inserted_at'));
    expect(poll?.[0]).toMatchObject({ skip_histogram: true, skip_field_stats: true, offset: 0 });
    // Not a rebuild: the page search was not re-run.
    expect(mocks.stream.mock.calls.length).toBe(streamsBefore);
    expect(mocks.async.mock.calls.length).toBe(asyncBefore);
    // A second tick re-delivers everything in the overlap; nothing duplicates.
    await act(async () => { await vi.advanceTimersByTimeAsync(15_500); });
    expect(screen.getByTestId('rows').textContent).toBe('e3,eLate,e2,e1');
  } finally {
    vi.useRealTimers();
  }
}, 30_000);
