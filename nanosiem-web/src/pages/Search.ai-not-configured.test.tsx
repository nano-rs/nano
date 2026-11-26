// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// NAN-5877: a failed search asks pivt for a fix. When AI is not set up the
// server answers 503 AI_NOT_CONFIGURED: the page says so in plain words,
// logs no error, and stops asking for the rest of the session. The page is
// rendered for real; only the network seam and heavy children are stubbed
// (same harness as Search.request-shape.test.tsx).
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const net = vi.hoisted(() => ({
  search: vi.fn(),
  fieldStats: vi.fn(),
  stream: vi.fn(),
  correctQuery: vi.fn(),
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
        : prop === 'correctQuery'
          ? net.correctQuery
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
        const q = 'source_type=windows_sysmon | stats coutn by device.hostname';
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

class FakeApiClientError extends Error {
  constructor(message: string, public code: string, public status: number) {
    super(message);
    this.name = 'ApiClientError';
  }
}

afterEach(cleanup);

beforeEach(() => {
  net.search.mockReset();
  net.fieldStats.mockReset().mockResolvedValue({ fields: [] });
  net.stream.mockReset().mockImplementation((_req: unknown, cb: Record<string, (d: unknown) => void>) => {
    cb.onError?.({ code: 'PARSE_ERROR', message: 'Parse error: unknown function coutn' });
    return { abort: vi.fn() };
  });
  net.correctQuery.mockReset().mockRejectedValue(
    new FakeApiClientError("AI isn't set up on this install yet.", 'AI_NOT_CONFIGURED', 503),
  );
});

describe('Search page when AI is not set up (NAN-5877)', () => {
  it('shows a plain hint, logs no error, and stops asking', async () => {
    const consoleError = vi.spyOn(console, 'error').mockImplementation(() => {});
    renderSearch();
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Type and run' })); });
    await waitFor(() => expect(net.correctQuery).toHaveBeenCalledTimes(1));
    expect((await screen.findByTestId('search-ai-not-configured')).textContent).toContain(
      "AI fix suggestions are off because AI isn't set up.",
    );
    expect(consoleError.mock.calls.some((c) => String(c[0]).includes('[QueryCorrection]'))).toBe(false);

    // A second failed search does not ask again.
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Type and run' })); });
    await waitFor(() => expect(net.stream).toHaveBeenCalledTimes(2));
    expect(net.correctQuery).toHaveBeenCalledTimes(1);
    consoleError.mockRestore();
  });
});
