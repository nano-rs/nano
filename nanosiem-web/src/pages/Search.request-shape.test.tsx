// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// NAN-5486: the request a drilldown and a table page change actually send.
// A drilldown (clicking a value in a `| top` / table view) sent POST
// /api/search without `table_view` or `skip_field_stats`: its rows came back
// as `SELECT *` plus every prevalence column, and the response waited on the
// all-column field-stats companion (1.1 s on a throwaway stack, ~6 s on a dev
// laptop, against ~0.2 s for the same query typed). A table page change also
// lacked `table_view`. The page is rendered for real; only the network seam
// (`useSearch` / `useFieldStats` / `api`) and heavy children are stubbed.
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
    useUpdateSavedSearch: idle,
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
  // The editor: "Run" types a query and runs it like Enter does.
  SearchQueryInput: ({ onQueryChange, onSearch }: { onQueryChange: (q: string) => void; onSearch: (...a: unknown[]) => void }) => (
    <button
      onClick={() => {
        const q = 'source_type=windows_sysmon | stats count by device.hostname';
        onQueryChange(q);
        onSearch(1, false, q);
      }}
    >
      Type and run
    </button>
  ),
  // The results view: a drilldown cell and a table pager.
  SearchResults: ({ onDrilldown, onPageChange }: { onDrilldown?: (f: Record<string, unknown>) => void; onPageChange?: (p: number) => void }) => (
    <>
      <button onClick={() => onDrilldown?.({ 'device.hostname': 'ws-legal-062.corp.local' })}>Drill</button>
      <button onClick={() => onPageChange?.(1)}>Next page</button>
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

const rows = (n: number) =>
  Array.from({ length: n }, (_, i) => ({ id: `r${i}`, timestamp: '2026-11-15T10:00:00Z', source_type: 'windows_sysmon', 'device.hostname': 'ws-legal-062.corp.local' }));

afterEach(cleanup);

beforeEach(() => {
  net.search.mockReset().mockResolvedValue({ results: rows(50), total_count: 2056, execution_time_ms: 120, histogram: [] });
  net.fieldStats.mockReset().mockResolvedValue({ fields: [] });
  net.stream.mockReset().mockImplementation((_req: unknown, cb: Record<string, (d: unknown) => void>) => {
    // A stats table with more groups than the first page holds.
    cb.onRows?.({ rows: rows(50) });
    cb.onMetadata?.({ total_count: 500, display_type: 'table', execution_time_ms: 90, histogram: [] });
    cb.onCompleted?.({ total_rows_delivered: 50 });
    return { abort: vi.fn() };
  });
});

describe('Search page rows requests (NAN-5486)', () => {
  it('a drilldown asks for the table view and fetches field stats in the background', async () => {
    renderSearch();
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Drill' })); });
    await waitFor(() => expect(net.search).toHaveBeenCalled());

    const [request] = net.search.mock.calls[0];
    expect(request).toMatchObject({
      query: 'device.hostname="ws-legal-062.corp.local"',
      offset: 0,
      table_view: true,
      skip_field_stats: true,
      dataset: 'logs',
    });
    expect(request.request_id).toEqual(expect.any(String));

    // The sidebar's stats follow as their own request, for the same run.
    await waitFor(() => expect(net.fieldStats).toHaveBeenCalled());
    const [stats] = net.fieldStats.mock.calls[0];
    expect(stats).toMatchObject({ query: request.query, request_id: request.request_id, dataset: 'logs' });
    expect(stats.start).toBe(request.time_range.start);
    expect(stats.end).toBe(request.time_range.end);
  });

  it('a table page change asks for the table view', async () => {
    renderSearch();
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Type and run' })); });
    await waitFor(() => expect(net.stream).toHaveBeenCalled());
    expect(net.stream.mock.calls[0][0]).toMatchObject({ table_view: true, skip_field_stats: true });

    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Next page' })); });
    await waitFor(() => expect(net.search).toHaveBeenCalled());
    expect(net.search.mock.calls[0][0]).toMatchObject({
      query: 'source_type=windows_sysmon | stats count by device.hostname',
      offset: 50,
      table_view: true,
      skip_field_stats: true,
      skip_histogram: true,
    });
  });
});
