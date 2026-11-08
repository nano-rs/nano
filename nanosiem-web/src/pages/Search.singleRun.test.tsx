// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
// NAN-3299 / NAN-3883: one user action reaches the search endpoint exactly
// once. Before the fix every run fired two or three searches: the run's own
// relative -> absolute URL rewrite was read as back/forward navigation by the
// URL-sync effect (which re-ran the search), and router location lag made the
// effect restore and re-run the PREVIOUS query. Drives the real query editor
// (Enter), the real time picker and the real Run button.
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Router, UNSAFE_createMemoryHistory } from 'react-router-dom';
import { useLayoutEffect, useState, type ReactNode } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Search } from './Search';
import { EditorView } from '@codemirror/view';
import userEvent from '@testing-library/user-event';

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
const searches = () => mocks.stream.mock.calls.length;
const queries = () => mocks.stream.mock.calls.map(call => (call[0] as { query?: string }).query?.trim());

async function mountEditor(container: HTMLElement, query: string) {
  const content = await waitFor(() => {
    const element = container.querySelector('.cm-content') as HTMLElement | null;
    expect(element).toBeTruthy();
    return element!;
  });
  const view = EditorView.findFromDOM(content)!;
  view.dispatch({ changes: { from: 0, insert: query } });
  await settle();
  return { content, view };
}

async function mountWithQuery(query: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const { container } = render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/search']}><Search /></MemoryRouter></QueryClientProvider>);
  return { container, ...(await mountEditor(container, query)) };
}

it('Enter, a time-range pick and the Run button each run the search exactly once', async () => {
  const { container, content } = await mountWithQuery('* | stats count by source_type');
  fireEvent.keyDown(content, { key: 'Enter', code: 'Enter', keyCode: 13 });
  await waitFor(() => expect(searches()).toBe(1));
  await settle();
  expect(searches()).toBe(1);

  const user = userEvent.setup({ pointerEventsCheck: 0 });
  await user.click(screen.getAllByRole('button').find(button => button.textContent?.includes('Last hour'))!);
  await user.click((await screen.findAllByText(/^7d$/)).at(-1)!);
  await waitFor(() => expect(searches()).toBe(2));
  await settle();
  expect(searches()).toBe(2);

  // A deliberate re-run of the same search later is still a new run.
  await new Promise(resolve => setTimeout(resolve, 1_600));
  fireEvent.click(container.querySelector('button.search-console-action')!);
  await waitFor(() => expect(searches()).toBe(3));
  await settle();
  expect(searches()).toBe(3);
  expect(mocks.history).toHaveBeenCalledTimes(3);
  expect(mocks.cancel).not.toHaveBeenCalled();
}, 20_000);

it('two deliberate Enters both run, even while the first is still in flight', async () => {
  // Hold the run in flight: the second Enter is a new user action, not an echo.
  mocks.stream.mockImplementation(() => new AbortController());
  const { content } = await mountWithQuery('* | stats count by source_type');
  fireEvent.keyDown(content, { key: 'Enter', code: 'Enter', keyCode: 13 });
  await waitFor(() => expect(searches()).toBe(1));
  fireEvent.keyDown(content, { key: 'Enter', code: 'Enter', keyCode: 13 });
  await waitFor(() => expect(searches()).toBe(2));
  await settle();
  expect(searches()).toBe(2);
  expect(mocks.history).toHaveBeenCalledTimes(2);
}, 20_000);

it('an explicit Enter after a passive URL load runs live (bypassing the cache)', async () => {
  // Hold the passive run in flight so the explicit run overlaps it.
  mocks.stream.mockImplementation(() => new AbortController());
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const { container } = render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/search?q=source_type%3D%22okta%22&run=true']}><Search /></MemoryRouter>
    </QueryClientProvider>,
  );
  await waitFor(() => expect(searches()).toBe(1));
  // The URL auto-run is passive: it may read the server cache. Every
  // interactive stream opts in to the NAN-4915 background-job hand-off
  // (`x-nano-accept-async: 1`), so acceptAsync rides along on both runs.
  expect(mocks.stream.mock.calls[0][2]).toEqual({ bypass: false, acceptAsync: true });
  const content = await waitFor(() => {
    const element = container.querySelector('.cm-content') as HTMLElement | null;
    expect(element).toBeTruthy();
    return element!;
  });
  await settle();
  fireEvent.keyDown(content, { key: 'Enter', code: 'Enter', keyCode: 13 });
  await waitFor(() => expect(searches()).toBe(2));
  expect((mocks.stream.mock.calls[1][0] as { query?: string }).query?.trim()).toBe('source_type="okta"');
  expect(mocks.stream.mock.calls[1][2]).toEqual({ bypass: true, acceptAsync: true });
  await settle();
  expect(searches()).toBe(2);
}, 20_000);

// A router whose location lags the URL the page wrote, like a transition
// that has not rendered yet. history (and so window.location) moves at once.
const lag = { deliver: () => {} };
function LaggingRouter({ children }: { children: ReactNode }) {
  const [history] = useState(() => UNSAFE_createMemoryHistory({ initialEntries: ['/search'], v5Compat: true }));
  const [state, setState] = useState({ action: history.action, location: history.location });
  useLayoutEffect(() => {
    let pending = state;
    lag.deliver = () => setState(pending);
    return history.listen(({ action, location }) => { pending = { action, location }; });
  }, [history]); // eslint-disable-line react-hooks/exhaustive-deps
  return <Router location={state.location} navigationType={state.action} navigator={history}>{children}</Router>;
}

it('a new query runs once while the location lags: never the previous query again, never twice', async () => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const { container } = render(<QueryClientProvider client={client}><LaggingRouter><Search /></LaggingRouter></QueryClientProvider>);
  const { content, view } = await mountEditor(container, 'source_type="apache_access" | stats count');
  const runWhileTheLocationLags = async () => {
    fireEvent.keyDown(content, { key: 'Enter', code: 'Enter', keyCode: 13 });
    await settle();
    await act(async () => { lag.deliver(); });
    await settle();
  };
  await runWhileTheLocationLags();
  expect(queries()).toEqual(['source_type="apache_access" | stats count']);

  view.dispatch({ changes: { from: 0, to: view.state.doc.length, insert: 'source_type="apache_error"' } });
  await settle();
  await runWhileTheLocationLags();
  expect(queries()).toEqual(['source_type="apache_access" | stats count', 'source_type="apache_error"']);
  expect(mocks.history).toHaveBeenCalledTimes(2);
  // The editor keeps what the analyst ran, not the restored previous query.
  expect(view.state.doc.toString()).toBe('source_type="apache_error"');
}, 20_000);
