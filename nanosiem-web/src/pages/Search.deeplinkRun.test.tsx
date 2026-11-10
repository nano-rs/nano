// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
// NAN-5235: a Search deep link never runs its query on navigation unless an
// in-app caller granted that exact run. A bare `run=true` (an external link,
// a bookmark) loads the query and asks for an explicit Run.
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Router } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Search } from './Search';
import { OUTSIDE_ARRIVAL_STATE, grantSearchAutoRun, isSearchAutoRunGranted, rememberTabSearch } from '@/lib/search-auto-run';

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

const settle = () => new Promise(resolve => setTimeout(resolve, 400));
// The SSE mock falls back to the async endpoint, so one run is one stream call.
const searches = () => mocks.stream.mock.calls.length;

// The first entry of a memory history is key "default", exactly like a
// document's landing entry. `inApp` puts the Search entry second, as an
// in-app navigation does.
function mountAt(url: string, { inApp = false, afterSignIn = false }: { inApp?: boolean; afterSignIn?: boolean } = {}) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const entries = inApp || afterSignIn
    ? ['/login', afterSignIn ? { pathname: '/search', hash: url.split('#')[1] ? `#${url.split('#')[1]}` : '', state: OUTSIDE_ARRIVAL_STATE } : url]
    : [url];
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={entries} initialIndex={entries.length - 1}><Search /></MemoryRouter>
    </QueryClientProvider>,
  );
}

it('a bare run=true link does not run, and offers an explicit Run', async () => {
  mountAt('/search#q=error%20%7C%20stats%20count&run=true');
  const prompt = await screen.findByTestId('linked-query-run-prompt');
  await settle();
  expect(searches()).toBe(0);

  fireEvent.click(within(prompt).getByRole('button', { name: 'Run' }));
  await waitFor(() => expect(mocks.stream).toHaveBeenCalledTimes(1));
  expect((mocks.stream.mock.calls[0][0] as { query?: string }).query?.trim()).toBe('error | stats count');
}, 20_000);

it('a forged or mismatched run value does not run', async () => {
  const otherQuery = grantSearchAutoRun('something else');
  for (const run of ['00000000-0000-4000-8000-000000000000', otherQuery]) {
    cleanup();
    vi.clearAllMocks();
    mountAt(`/search#q=error&run=${run}`);
    await screen.findByTestId('linked-query-run-prompt');
    await settle();
    expect(searches()).toBe(0);
  }
}, 20_000);

it('an in-app grant runs once and is consumed', async () => {
  const token = grantSearchAutoRun('error');
  mountAt(`/search#q=error&run=${token}`);
  await waitFor(() => expect(mocks.stream).toHaveBeenCalledTimes(1));
  await settle();
  expect(searches()).toBe(1);
  expect(screen.queryByTestId('linked-query-run-prompt')).toBeNull();
  expect(isSearchAutoRunGranted(token, 'error')).toBe(false);
}, 20_000);

it('a plain #q= link opened from elsewhere does not run', async () => {
  mountAt('/search#q=error&time=Last+hour');
  await screen.findByTestId('linked-query-run-prompt');
  await settle();
  expect(searches()).toBe(0);
}, 20_000);

it('a query this tab already ran re-runs on reload without a prompt', async () => {
  rememberTabSearch('error');
  mountAt('/search#q=error&time=Last+hour');
  await waitFor(() => expect(mocks.stream).toHaveBeenCalledTimes(1));
  expect(screen.queryByTestId('linked-query-run-prompt')).toBeNull();
}, 20_000);

it('an in-app navigation to a #q= link still runs it', async () => {
  mountAt('/search#q=error&time=Last+hour', { inApp: true });
  await waitFor(() => expect(mocks.stream).toHaveBeenCalledTimes(1));
  expect(screen.queryByTestId('linked-query-run-prompt')).toBeNull();
}, 20_000);

it('the return to a #q= link after sign-in does not run it', async () => {
  mountAt('/search#q=error&time=Last+hour', { afterSignIn: true });
  await screen.findByTestId('linked-query-run-prompt');
  await settle();
  expect(searches()).toBe(0);
}, 20_000);

// A controlled router models what the browser hands React Router: a fragment
// navigation performed by another window creates an entry with no history
// state, i.e. key "default"; an entry the app created carries its own key.
function controlledSearch() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const navigator = {
    createHref: (to: unknown) => (typeof to === 'string' ? to : `${(to as { pathname?: string }).pathname ?? ''}${(to as { hash?: string }).hash ?? ''}`),
    push: vi.fn(), replace: vi.fn(), go: vi.fn(),
  };
  const at = (hash: string, key: string) => (
    <QueryClientProvider client={client}>
      <Router location={{ pathname: '/search', search: '', hash, state: null, key }} navigator={navigator}><Search /></Router>
    </QueryClientProvider>
  );
  return { at };
}

it('a fragment navigation from another window does not run its query', async () => {
  const { at } = controlledSearch();
  const view = render(at('', 'default'));
  await settle();
  view.rerender(at('#q=error%20%7C%20stats%20count', 'default'));
  await screen.findByTestId('linked-query-run-prompt');
  await settle();
  expect(searches()).toBe(0);
}, 20_000);

it('an in-app history entry with a new query still runs it', async () => {
  const { at } = controlledSearch();
  const view = render(at('', 'default'));
  await settle();
  view.rerender(at('#q=error%20%7C%20stats%20count', 'k1'));
  await waitFor(() => expect(mocks.stream).toHaveBeenCalledTimes(1));
  expect(screen.queryByTestId('linked-query-run-prompt')).toBeNull();
}, 20_000);

it('a shared ?s= link opened from outside loads the search and waits for Run', async () => {
  mocks.mutation.mockResolvedValue({ query: 'error', query_mode: 'piped', time_range_preset: 'Last hour' });
  mountAt('/search#s=abc123');
  const prompt = await screen.findByTestId('linked-query-run-prompt');
  await settle();
  expect(searches()).toBe(0);
  fireEvent.click(within(prompt).getByRole('button', { name: 'Run' }));
  await waitFor(() => expect(mocks.stream).toHaveBeenCalledTimes(1));
}, 20_000);

it('a shared ?s= link followed inside the app still runs', async () => {
  mocks.mutation.mockResolvedValue({ query: 'error', query_mode: 'piped', time_range_preset: 'Last hour' });
  mountAt('/search#s=abc123', { inApp: true });
  await waitFor(() => expect(mocks.stream).toHaveBeenCalledTimes(1));
}, 20_000);
