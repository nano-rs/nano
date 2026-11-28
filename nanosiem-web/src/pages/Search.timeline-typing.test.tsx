// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// NAN-5950 (Sentry NANO-FRONTEND-3): typing in the query editor re-renders the
// Search page once per key. The timeline must not re-render with it: every
// prop Search passes it keeps its identity, so the memoized
// TimelineVisualization skips the render. The page is rendered for real;
// only the network seam and heavy children are stubbed (same harness as
// Search.ai-not-configured.test.tsx).
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { memo } from 'react';

const timeline = vi.hoisted(() => ({ renders: 0, props: [] as Record<string, unknown>[] }));
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
  // Same memo as the real component: it renders only when a prop changes.
  TimelineVisualization: memo((props: Record<string, unknown>) => {
    timeline.renders += 1;
    timeline.props.push(props);
    return <div data-testid="timeline-stub" />;
  }),
  FieldsPanel: () => null,
  SavedQueriesPalette: () => null,
  SearchJobsModal: () => null,
  PrevalenceSlider: () => null,
  DatasetSelector: () => null,
  // The editor: each click types one more character (no run).
  SearchQueryInput: ({ query, onQueryChange }: { query: string; onQueryChange: (q: string) => void }) => (
    <button data-query={query} onClick={() => onQueryChange(`${query ?? ''}x`)}>Type a key</button>
  ),
  SearchResults: () => null,
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

afterEach(cleanup);

beforeEach(() => {
  timeline.renders = 0;
  timeline.props = [];
  net.search.mockReset();
  net.fieldStats.mockReset().mockResolvedValue({ fields: [] });
  net.stream.mockReset().mockReturnValue({ abort: vi.fn() });
  net.correctQuery.mockReset();
});

describe('Search page typing and the timeline (NAN-5950)', () => {
  it('typing in the query editor does not re-render the timeline', async () => {
    renderSearch();
    await act(async () => { await new Promise(r => setTimeout(r, 50)); });
    expect(screen.getByTestId('timeline-stub')).toBeTruthy();
    const before = timeline.renders;
    const last = timeline.props[timeline.props.length - 1];
    for (let i = 0; i < 6; i++) {
      await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Type a key' })); });
    }
    // The keys landed: the page re-rendered with the new draft query.
    expect(screen.getByRole('button', { name: 'Type a key' }).getAttribute('data-query')).toMatch(/x{6}$/);
    // A prop whose identity changed per key would show up here by name.
    const changed = timeline.props.slice(before).flatMap(p =>
      Object.keys(p).filter(k => p[k] !== last[k]),
    );
    expect(changed).toEqual([]);
    expect(timeline.renders).toBe(before);
  });
});
