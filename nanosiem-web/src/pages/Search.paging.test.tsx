// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// NAN-5703: infinite-scroll paging on the real Search page. A burst of
// scroll events loads each page once, and every new result set (a run, a
// drilldown) pages from its own page 2, never the previous set's next page.
// Same harness as Search.request-shape.test.tsx: only the network seam and
// heavy children are stubbed.
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const net = vi.hoisted(() => ({
  search: vi.fn(),
  fieldStats: vi.fn(),
  stream: vi.fn(),
}));

vi.mock('@/hooks/use-api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/hooks/use-api')>();
  const idle = () => ({ mutate: vi.fn(async () => ({})), loading: false });
  return {
    ...actual,
    useSearch: () => ({ mutate: net.search, loading: false }),
    useFieldStats: () => ({ mutate: net.fieldStats, loading: false }),
    useSearchSql: idle,
    useExplainQuery: idle,
    useSearchFieldValues: idle,
    useCreateSavedSearch: idle,
    useDeleteSavedSearch: idle,
    useShareSavedSearch: idle,
    useCreateSharedSearch: idle,
    useGetSharedSearch: idle,
    useStoreQueryExplanation: idle,
    useGetQueryExplanation: idle,
    useSavedSearches: () => ({ data: [], refetch: vi.fn() }),
    useSharedSearches: () => ({ data: [] }),
    useMelodStatus: () => ({ data: null }),
  };
});

vi.mock('@/lib/api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/lib/api')>();
  const api = new Proxy({} as Record<string, unknown>, {
    get: (_t, prop) =>
      prop === 'searchStreamSSE'
        ? net.stream
        : vi.fn(async () => (String(prop).startsWith('list') ? [] : {})),
  });
  return { ...actual, api };
});

vi.mock('@/contexts/UserPreferencesContext', () => ({
  useUserPreferences: () => ({ defaultTimeRange: '7d', queryMode: 'piped' }),
}));
vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({ user: { id: 'u1', email: 'a@b.c' }, hasPermission: () => true, isAuthenticated: true }),
}));
vi.mock('@/contexts/ScrollContainerContext', () => ({ useScrollContainer: () => null }));
vi.mock('@/contexts/PageContext', () => ({ useHereCardOverride: () => {}, usePageContext: () => ({ pageKey: 'search', hereCard: null, setHereCard: () => {} }) }));
vi.mock('@/enterprise/contexts/NotebookContext', () => ({
  useNotebookCapture: () => ({ captureSearch: vi.fn(), isActive: false, addEntityToNotebook: vi.fn(), addEntitiesToNotebook: vi.fn() }),
}));
vi.mock('@/enterprise/hooks/use-melod-job', () => ({ useMelodJob: () => ({}) }));
vi.mock('@/hooks/use-capabilities', () => ({ useCapabilities: () => ({ capabilities: { melod: false, edition: 'enterprise' } }) }));
vi.mock('@/hooks/useSearchHistory', () => ({
  useSearchHistory: () => ({
    searchHistory: [], historyEnabled: false, toggleHistoryEnabled: vi.fn(),
    clearSearchHistory: vi.fn(), addToSearchHistory: vi.fn(), refreshHistory: vi.fn(),
  }),
}));
vi.mock('@/hooks/useSchemaFieldMap', () => ({ useSchemaFieldMap: () => null }));
vi.mock('@/hooks/use-mobile', () => ({ useIsMobile: () => false }));
vi.mock('@/hooks/useDocumentTitle', () => ({ useDocumentTitle: () => {} }));
vi.mock('@/components/DemoHints', () => ({ SearchDemoHint: () => null }));
vi.mock('@/components/reports/ScheduleReportDialog', () => ({ ScheduleReportDialog: () => null }));
vi.mock('@/components/dashboard', () => ({ AddToDashboardDialog: () => null }));
vi.mock('@/components/search', () => ({
  FIELD_STATS_PINNED_COLUMNS: ['source_type'],
  TimelineVisualization: () => null,
  FieldsPanel: () => null,
  SavedQueriesPalette: () => null,
  SearchJobsModal: () => null,
  PrevalenceSlider: () => null,
  DatasetSelector: () => null,
  SearchQueryInput: ({ onQueryChange, onSearch }: { onQueryChange: (q: string) => void; onSearch: (...a: unknown[]) => void }) => (
    <button
      onClick={() => {
        const q = 'source_type=windows_sysmon';
        onQueryChange(q);
        onSearch(1, false, q);
      }}
    >
      Type and run
    </button>
  ),
  // The results view: rows shown, a scroll burst, and a drilldown cell.
  SearchResults: ({ results, isSearching, onDrilldown, onLoadMore }: { results: unknown[]; isSearching?: boolean; onDrilldown?: (f: Record<string, unknown>) => void; onLoadMore?: () => void }) => (
    <>
      <span data-testid="shown" data-searching={String(Boolean(isSearching))}>{results.length}</span>
      <button onClick={() => { onLoadMore?.(); onLoadMore?.(); onLoadMore?.(); }}>Scroll burst</button>
      <button onClick={() => onDrilldown?.({ 'device.hostname': 'ws-legal-062.corp.local' })}>Drill</button>
    </>
  ),
}));

import { Search } from './Search';

function renderSearch() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/search']}>
        <Search />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const rows = (n: number, from = 0) =>
  Array.from({ length: n }, (_, i) => ({ id: `r${from + i}`, timestamp: '2026-11-15T10:00:00Z', source_type: 'windows_sysmon' }));

const offsets = () => net.search.mock.calls.map(([req]) => (req as { offset: number }).offset);

afterEach(cleanup);

beforeEach(() => {
  net.search.mockReset().mockImplementation(async (req: { offset: number }) => ({
    results: rows(50, req.offset), total_count: 1085, execution_time_ms: 10, histogram: [],
  }));
  net.fieldStats.mockReset().mockResolvedValue({ fields: [] });
  // Like a real SSE stream, events arrive after the controller is returned.
  net.stream.mockReset().mockImplementation((_req: unknown, cb: Record<string, (d: unknown) => void>) => {
    setTimeout(() => {
      cb.onRows?.({ rows: rows(50) });
      cb.onMetadata?.({ total_count: 1085, display_type: 'events', execution_time_ms: 9, histogram: [] });
      cb.onCompleted?.({ total_rows_delivered: 50 });
    }, 0);
    return { abort: vi.fn() };
  });
});

/** Like the real list, scroll only once the page is idle (its scroll
 *  handler is detached while `isSearching`). */
async function scroll() {
  await waitFor(() => expect(screen.getByTestId('shown').dataset.searching).toBe('false'));
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Scroll burst' })); });
}

describe('Search page infinite scroll (NAN-5703)', () => {
  it('a burst of scroll events loads the next page once', async () => {
    renderSearch();
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Type and run' })); });
    await waitFor(() => expect(screen.getByTestId('shown').textContent).toBe('50'));
    await scroll();
    await waitFor(() => expect(screen.getByTestId('shown').textContent).toBe('100'));
    await scroll();
    await waitFor(() => expect(screen.getByTestId('shown').textContent).toBe('150'));
    expect(offsets()).toEqual([50, 100]);
  });

  it('a drilldown pages from its own page 2, not the previous search\'s next page', async () => {
    renderSearch();
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Type and run' })); });
    await waitFor(() => expect(screen.getByTestId('shown').textContent).toBe('50'));
    await scroll();
    await scroll();
    await waitFor(() => expect(screen.getByTestId('shown').textContent).toBe('150'));

    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Drill' })); });
    await waitFor(() => expect(offsets()).toEqual([50, 100, 0]));
    await waitFor(() => expect(screen.getByTestId('shown').textContent).toBe('50'));
    await scroll();
    await waitFor(() => expect(screen.getByTestId('shown').textContent).toBe('100'));
    // Before the fix the drilldown's next page was the old search's page 4.
    expect(offsets()).toEqual([50, 100, 0, 50]);
    // ...and it pages the drilldown's own query.
    const [first, second] = [net.search.mock.calls[2][0], net.search.mock.calls[3][0]] as { query: string }[];
    expect(first.query).toContain('device.hostname="ws-legal-062.corp.local"');
    expect(second.query).toBe(first.query);
  });
});
