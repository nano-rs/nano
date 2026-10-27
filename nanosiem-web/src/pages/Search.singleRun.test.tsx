// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
// NAN-3883: one user action reaches /api/search exactly once. A production tenant showed two
// or three /api/search per run (three 30d scans on the cell per click). This
// drives the real query editor (Enter), the real time picker and the real
// Run button, with the real results/stats/timeline components mounted.
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
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
  return { ...original, ...hooks, useSearch: () => ({ mutate: mocks.legacy }), useFieldStats: () => ({ mutate: mocks.fields }) };
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

const settle = () => new Promise(resolve => setTimeout(resolve, 400));

async function mountWithQuery(query: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  client.setQueryData(['schema-fields'], mocks.schema);
  const { container } = render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/search']}><Search /></MemoryRouter></QueryClientProvider>);
  const content = await waitFor(() => {
    const element = container.querySelector('.cm-content') as HTMLElement | null;
    expect(element).toBeTruthy();
    return element!;
  });
  EditorView.findFromDOM(content)!.dispatch({ changes: { from: 0, insert: query } });
  await settle();
  return { container, content };
}

const searches = () => mocks.interactive.mock.calls.length;

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
  // One history entry per run, no superseded request to cancel.
  expect(mocks.history).toHaveBeenCalledTimes(3);
  expect(mocks.cancel).not.toHaveBeenCalled();
}, 20_000);

it('a repeated trigger of the same run moments later joins it instead of starting the scan again', async () => {
  const { container, content } = await mountWithQuery('* | stats count by source_type');
  fireEvent.keyDown(content, { key: 'Enter', code: 'Enter', keyCode: 13 });
  fireEvent.keyDown(content, { key: 'Enter', code: 'Enter', keyCode: 13 });
  fireEvent.click(container.querySelector('button.search-console-action')!);
  await waitFor(() => expect(searches()).toBe(1));
  await settle();
  expect(searches()).toBe(1);
  expect(mocks.history).toHaveBeenCalledTimes(1);
  expect(mocks.cancel).not.toHaveBeenCalled();
  // A different search right away is a new run.
  EditorView.findFromDOM(content)!.dispatch({ changes: { from: 0, insert: 'actor.user.name="x" ' } });
  await settle();
  fireEvent.keyDown(content, { key: 'Enter', code: 'Enter', keyCode: 13 });
  await waitFor(() => expect(searches()).toBe(2));
}, 20_000);

// NAN-3809: exercise the actual pasted-URL admission and deliberate rerun.
it('an absolute pasted URL reads cache, while Run of that same query stays live', async () => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  client.setQueryData(['schema-fields'], mocks.schema);
  const entry = '/search?q=metadata.log_source%3D%22conduit_proxy%22&start=2026-10-06T11%3A53%3A42.000Z&end=2026-10-06T12%3A53%3A42.999Z';
  const { container } = render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[entry]}><Search /></MemoryRouter></QueryClientProvider>);
  await waitFor(() => expect(mocks.interactive).toHaveBeenCalledTimes(1));
  expect(mocks.interactive.mock.calls[0][0]).toMatchObject({ use_cache: true, query: 'metadata.log_source="conduit_proxy"' });
  await settle();
  await new Promise(resolve => setTimeout(resolve, 1_600));
  fireEvent.click(container.querySelector('button.search-console-action')!);
  await waitFor(() => expect(mocks.interactive).toHaveBeenCalledTimes(2));
  expect(mocks.interactive.mock.calls[1][0]).toMatchObject({ use_cache: false });
}, 20_000);

it('a relative pasted URL never opts into cache', async () => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  client.setQueryData(['schema-fields'], mocks.schema);
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/search?q=error&time=Last+hour']}><Search /></MemoryRouter></QueryClientProvider>);
  await waitFor(() => expect(mocks.interactive).toHaveBeenCalledTimes(1));
  expect(mocks.interactive.mock.calls[0][0]).toMatchObject({ use_cache: false });
}, 20_000);

it('a cached pasted URL shows its age and Refresh bypasses cache', async () => {
  mocks.interactive.mockImplementationOnce(async (_request, _retry, onMeta) => {
    onMeta?.({ hit: true, ageSecs: 120 });
    return { results: [{ message: 'cached event' }], total_count: 1, fields: [], execution_time_ms: 0 };
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  client.setQueryData(['schema-fields'], mocks.schema);
  const entry = '/search?q=error&start=2026-10-06T11:53:42.000Z&end=2026-10-06T12:53:42.999Z';
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[entry]}><Search /></MemoryRouter></QueryClientProvider>);
  const refresh = await screen.findByRole('button', { name: /cached .* ago · refresh/i });
  await new Promise(resolve => setTimeout(resolve, 1_600));
  fireEvent.click(refresh);
  await waitFor(() => expect(mocks.interactive).toHaveBeenCalledTimes(2));
  expect(mocks.interactive.mock.calls[1][0]).toMatchObject({ use_cache: false });
}, 20_000);

it('a fresh fired-rule deep link honors absolute bounds over a relative preset and preferences', async () => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  client.setQueryData(['schema-fields'], mocks.schema);
  const entry = '/search?q=error&time=Last+hour&start=2026-10-06T11%3A53%3A42.000Z&end=2026-10-06T12%3A53%3A42.999Z';
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[entry]}><Search /></MemoryRouter></QueryClientProvider>);
  await waitFor(() => expect(mocks.interactive).toHaveBeenCalledTimes(1));
  expect(mocks.interactive.mock.calls[0][0].time_range).toEqual({ start: '2026-10-06T11:53:42.000Z', end: '2026-10-06T12:53:42.999Z' });
});
