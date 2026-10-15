// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
// NAN-3883: the production sequence. Each click reached /api/search three times:
// twice with the new query and once with the PREVIOUS query (ingress 05:56:26Z:
// a 400 for the previous, invalid query beside two 200s for the new one).
// React Router delivers a location inside startTransition, so urgent renders
// right after the page's own URL write still carry the old searchParams; the
// URL-sync effect re-runs on every render (handleSearch changes identity each
// render in production: useSearch() binds a fresh mutate) and read that lag
// as back/forward navigation. This router holds the location back like a
// pending transition and the search hook churns identity like production.
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { Router, UNSAFE_createMemoryHistory } from 'react-router-dom';
import { useLayoutEffect, useState, type ReactNode } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Search } from './Search';
import { EditorView } from '@codemirror/view';
import userEvent from '@testing-library/user-event';

const mocks = vi.hoisted(() => ({
  interactive: vi.fn(), async: vi.fn(), fields: vi.fn(), legacy: vi.fn(), poll: vi.fn(), page: vi.fn(),
  histogram: vi.fn(), panel: vi.fn(),
  cancel: vi.fn().mockResolvedValue({}), cancelJob: vi.fn().mockResolvedValue({}),
  stream: vi.fn(), tenantPlan: undefined as object | undefined,
  noop: vi.fn(), mutation: vi.fn().mockResolvedValue({}), history: vi.fn(),
  schema: { schema: 'ocsf', fields: [{ name: 'enrichments.data.host_count' }] },
}));
vi.mock('@/lib/api', () => ({
  ApiClientError: class extends Error {},
  api: {
    searchInteractive: mocks.interactive, searchAsync: mocks.async, searchHistogram: mocks.histogram,
    getSearchJob: mocks.poll, getSearchJobResultPage: mocks.page,
    cancelSearch: mocks.cancel, cancelSearchJob: mocks.cancelJob,
    searchStreamSSE: mocks.stream,
    getExtFieldNames: async () => [], getSchemaFields: async () => mocks.schema, listSearchJobs: async () => [],
  },
}));
vi.mock('@/hooks/use-api', async importOriginal => {
  const original = await importOriginal<typeof import('@/hooks/use-api')>();
  const hooks = Object.fromEntries(Object.keys(original).filter(key => key.startsWith('use')).map(key => [key, () => ({
    mutate: mocks.mutation, data: undefined, loading: false, refetch: mocks.noop,
  })]));
  return { ...original, ...hooks, useSearch: () => ({ mutate: (...args: unknown[]) => mocks.legacy(...args) }), useFieldStats: () => ({ mutate: mocks.fields }) };
});
vi.mock('@/hooks/use-capabilities', async importOriginal => ({ ...(await importOriginal<object>()), useCapabilities: () => ({ capabilities: {}, tenantPlan: mocks.tenantPlan }) }));
vi.mock('@/contexts/AuthContext', () => ({ useAuth: () => ({ user: {}, hasPermission: () => true, isAuthenticated: true }) }));
vi.mock('@/contexts/UserPreferencesContext', () => ({ useUserPreferences: () => ({ defaultTimeRange: '1h', queryMode: 'piped' }) }));
vi.mock('@/contexts/PageContext', () => ({ useHereCardOverride: () => {} }));
vi.mock('@/enterprise/contexts/NotebookContext', () => ({ useNotebookCapture: () => ({ captureSearch: mocks.noop }) }));
vi.mock('@/enterprise/hooks/use-melod-job', () => ({ useMelodJob: () => ({ loading: false }) }));
vi.mock('@/hooks/useSearchHistory', () => ({ useSearchHistory: () => ({ searchHistory: [], addToSearchHistory: mocks.history, refreshHistory: mocks.noop }) }));
vi.mock('@/hooks/use-mobile', () => ({ useIsMobile: () => false }));

vi.mock('@/components/search/retro/useRetro', () => ({ primeDurableRetroResult: () => {} }));
vi.mock('@/enterprise/components/search/AnalyzeView', () => ({ AnalyzeView: () => null }));
vi.mock('@/components/reports/ScheduleReportDialog', () => ({ ScheduleReportDialog: () => null }));
vi.mock('@/components/dashboard', () => ({ AddToDashboardDialog: () => null }));
vi.mock('@/components/DemoHints', () => ({ SearchDemoHint: () => null }));
(globalThis as unknown as { ResizeObserver: unknown }).ResizeObserver ??= class { observe() {} unobserve() {} disconnect() {} };

beforeEach(() => {
  vi.clearAllMocks();
  localStorage.clear();
  sessionStorage.clear();
  mocks.tenantPlan = { identity: { permissions: [] }, components: {} };
  mocks.fields.mockResolvedValue({ fields: [] });
  mocks.histogram.mockResolvedValue({ histogram: [] });
  mocks.stream.mockImplementation((_request, callbacks) => {
    queueMicrotask(() => callbacks.onError?.({ code: 'VALIDATION_ERROR', message: 'gen1 tenant' }));
    return new AbortController();
  });
  mocks.interactive.mockImplementation(async () => ({
    results: [{ source_type: 'windows_sysmon', count: 2 }], total_count: 1, fields: [], execution_time_ms: 1, display_type: 'table',
  }));
});
afterEach(cleanup);

type Lagging = { deliver: () => void };
const lag: Lagging = { deliver: () => {} };

// A router whose location lags the URL the page wrote, like a transition
// that has not rendered yet. history (and so window.location) moves at once.
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

const settle = () => new Promise(resolve => setTimeout(resolve, 400));
const queries = () => mocks.interactive.mock.calls.map(call => (call[0] as { query?: string }).query?.trim());

async function mount(query: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  client.setQueryData(['schema-fields'], mocks.schema);
  const { container } = render(<QueryClientProvider client={client}><LaggingRouter><Search /></LaggingRouter></QueryClientProvider>);
  const content = await waitFor(() => {
    const element = container.querySelector('.cm-content') as HTMLElement | null;
    expect(element).toBeTruthy();
    return element!;
  });
  const view = EditorView.findFromDOM(content)!;
  view.dispatch({ changes: { from: 0, insert: query } });
  await settle();
  return { container, content, view };
}

async function runWhileTheLocationLags(content: HTMLElement) {
  fireEvent.keyDown(content, { key: 'Enter', code: 'Enter', keyCode: 13 });
  // Urgent renders (results, timeline, isSearching) land before the router
  // delivers the URL the run just wrote.
  await settle();
  await act(async () => { lag.deliver(); });
  await settle();
}

it('a new query runs once: never the previous query again, never twice', async () => {
  const { content, view } = await mount('metadata.log_source="apache_access" | stats dc(http_request.url.path)');
  await runWhileTheLocationLags(content);
  expect(queries()).toEqual(['metadata.log_source="apache_access" | stats dc(http_request.url.path)']);

  view.dispatch({ changes: { from: 0, to: view.state.doc.length, insert: 'source_type="apache_access"' } });
  await settle();
  await runWhileTheLocationLags(content);
  expect(queries()).toEqual([
    'metadata.log_source="apache_access" | stats dc(http_request.url.path)',
    'source_type="apache_access"',
  ]);
  expect(mocks.history).toHaveBeenCalledTimes(2);
  expect(mocks.cancel).not.toHaveBeenCalled();
  // The editor keeps what the analyst ran, not the restored previous query.
  expect(view.state.doc.toString()).toBe('source_type="apache_access"');
}, 20_000);

it('a time-range pick runs once while the location lags', async () => {
  const { content } = await mount('* | stats count(source_type) by source_type');
  await runWhileTheLocationLags(content);
  expect(queries()).toHaveLength(1);
  const user = userEvent.setup({ pointerEventsCheck: 0 });
  await user.click(screen.getAllByRole('button').find(button => button.textContent?.includes('Last hour'))!);
  await user.click((await screen.findAllByText(/^30d$/)).at(-1)!);
  await settle();
  await act(async () => { lag.deliver(); });
  await settle();
  expect(queries()).toHaveLength(2);
  expect(mocks.history).toHaveBeenCalledTimes(2);
  expect(mocks.cancel).not.toHaveBeenCalled();
}, 20_000);
