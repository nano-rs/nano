// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
// G6-G10 port (NAN-4927): Search URL state — fragments, relative ranges,
// fired-rule windows.
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Search } from './Search';
import { grantSearchAutoRun } from '@/lib/search-auto-run';

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
    search: async () => ({ results: [], total_count: 0, fields: [] }),
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
    results: [{ source_type: 'windows_sysmon', count: 2 }], total_count: 1, fields: [], execution_time_ms: 1, display_type: 'table',
  }));
});
afterEach(cleanup);


function LocationProbe() {
  const location = useLocation();
  return <output data-testid="location">{`${location.search}|${location.hash}`}</output>;
}

function mount(entry: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[entry]}><Search /><LocationProbe /></MemoryRouter>
    </QueryClientProvider>,
  );
}

const location = () => screen.getByTestId('location').textContent ?? '';
const fragment = () => new URLSearchParams(location().split('|')[1]?.replace(/^#/, '') ?? '');

// #7041: hunt queries live in the fragment, so they never reach the server or
// proxy access logs. Old `?q=` links still run and are migrated in place.
it('migrates a legacy ?q= link into the fragment and still runs it over its bounds', async () => {
  mount(`/search?q=error&start=2026-10-17T12%3A00%3A00.000Z&end=2026-10-17T12%3A30%3A00.000Z&run=${grantSearchAutoRun('error')}`);
  await waitFor(() => expect(mocks.stream).toHaveBeenCalledTimes(1));
  expect((mocks.stream.mock.calls[0][0] as { query?: string }).query?.trim()).toBe('error');
  expect((mocks.stream.mock.calls[0][0] as { time_range?: unknown }).time_range).toEqual({
    start: '2026-10-17T12:00:00.000Z', end: '2026-10-17T12:30:00.000Z',
  });
  await waitFor(() => expect(location().startsWith('|#')).toBe(true));
  expect(fragment().get('q')).toBe('error');
}, 20_000);

// NAN-3884: a relative pick stays relative in the URL after the run, so the
// same link opened later re-resolves against "now".
it('keeps a "Last 15 minutes" link relative after it runs', async () => {
  mount(`/search#q=error&time=Last+15+minutes&run=${grantSearchAutoRun('error')}`);
  await waitFor(() => expect(mocks.stream).toHaveBeenCalledTimes(1));
  const range = (mocks.stream.mock.calls[0][0] as { time_range: { start: string; end: string } }).time_range;
  expect(Date.parse(range.end) - Date.parse(range.start)).toBe(15 * 60_000);
  await waitFor(() => expect(fragment().get('run')).toBeNull());
  expect(fragment().get('time')).toBe('Last 15 minutes');
  expect(fragment().get('start')).toBeNull();
  expect(fragment().get('end')).toBeNull();
  expect(location().split('|')[0]).toBe('');
}, 20_000);

// #7030: a fired-rule pivot's absolute window wins over a relative preset.
it('a fired-rule deep link honors absolute bounds over a relative preset', async () => {
  mount(`/search#q=error&time=Last+hour&start=2026-10-06T11%3A53%3A42.000Z&end=2026-10-06T12%3A53%3A42.999Z&run=${grantSearchAutoRun('error')}`);
  await waitFor(() => expect(mocks.stream).toHaveBeenCalledTimes(1));
  expect((mocks.stream.mock.calls[0][0] as { time_range?: unknown }).time_range).toEqual({
    start: '2026-10-06T11:53:42.000Z', end: '2026-10-06T12:53:42.999Z',
  });
}, 20_000);

// NAN-4927 review: `view=rarity` is fragment state owned by Search; a run
// keeps it and nothing writes it back to the query string.
it('keeps #view=rarity in the fragment across a run, never in the query string', async () => {
  mount(`/search#q=error&time=Last+15+minutes&view=rarity&run=${grantSearchAutoRun('error')}`);
  await waitFor(() => expect(mocks.stream).toHaveBeenCalledTimes(1));
  await waitFor(() => expect(fragment().get('run')).toBeNull());
  expect(fragment().get('view')).toBe('rarity');
  expect(location().split('|')[0]).toBe('');
}, 20_000);
