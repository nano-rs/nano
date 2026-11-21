// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// NAN-5696: the Save query dialog's description was never sent.
// NAN-5695: the saved-queries palette was mounted without edit/delete
// handlers, so a saved query could not be changed or removed anywhere.
// The page is rendered for real; the network seam (`use-api` hooks / `api`)
// and heavy children are stubbed. The palette stub exposes the handlers the
// page passes so their wiring can be driven.
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const net = vi.hoisted(() => ({
  stream: vi.fn(),
  create: vi.fn(),
  update: vi.fn(),
  remove: vi.fn(),
  refetchSaved: vi.fn(),
}));

vi.mock('@/hooks/use-api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/hooks/use-api')>();
  const idle = () => ({ mutate: vi.fn(async () => ({})), loading: false });
  return {
    ...actual,
    useSearch: idle,
    useFieldStats: idle,
    useSearchSql: idle,
    useExplainQuery: idle,
    useSearchFieldValues: idle,
    useCreateSavedSearch: () => ({ mutate: net.create, loading: false }),
    useUpdateSavedSearch: () => ({ mutate: net.update, loading: false }),
    useDeleteSavedSearch: () => ({ mutate: net.remove, loading: false }),
    useShareSavedSearch: idle,
    useCreateSharedSearch: idle,
    useGetSharedSearch: idle,
    useStoreQueryExplanation: idle,
    useGetQueryExplanation: idle,
    useSavedSearches: () => ({ data: [], refetch: net.refetchSaved }),
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
  SearchJobsModal: () => null,
  PrevalenceSlider: () => null,
  DatasetSelector: () => null,
  SearchResults: () => null,
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
  SavedQueriesPalette: ({
    onUpdateQuery,
    onDeleteQuery,
  }: {
    onUpdateQuery?: (id: string, c: { name: string; query: string; description: string }) => Promise<unknown>;
    onDeleteQuery?: (id: string) => Promise<unknown>;
  }) => (
    <>
      <button
        disabled={!onUpdateQuery}
        onClick={() => { void onUpdateQuery?.('ss_1', { name: 'renamed', query: 'user=root', description: '' }); }}
      >
        Palette edit
      </button>
      <button disabled={!onDeleteQuery} onClick={() => { void onDeleteQuery?.('ss_1'); }}>
        Palette delete
      </button>
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

afterEach(cleanup);

beforeEach(() => {
  for (const fn of [net.create, net.update, net.remove, net.refetchSaved]) fn.mockReset();
  net.create.mockResolvedValue({ id: 'ss_new' });
  net.update.mockResolvedValue({ id: 'ss_1' });
  net.remove.mockResolvedValue(undefined);
  net.stream.mockReset().mockImplementation((_req: unknown, cb: Record<string, (d: unknown) => void>) => {
    cb.onRows?.({ rows: [] });
    cb.onMetadata?.({ total_count: 0, display_type: 'table', execution_time_ms: 5, histogram: [] });
    cb.onCompleted?.({ total_rows_delivered: 0 });
    return { abort: vi.fn() };
  });
});

async function openSaveDialog() {
  renderSearch();
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Type and run' })); });
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Save', exact: true } as never)); });
}

describe('Save query dialog (NAN-5696)', () => {
  it('sends the typed description with the saved query', async () => {
    await openSaveDialog();
    fireEvent.change(screen.getByPlaceholderText('e.g. Failed console logins'), { target: { value: 'sysmon by host' } });
    fireEvent.change(screen.getByPlaceholderText('Short explanation for your team'), {
      target: { value: '  Process launches across the fleet  ' },
    });
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Save query' })); });

    await waitFor(() => expect(net.create).toHaveBeenCalledTimes(1));
    expect(net.create.mock.calls[0][0]).toMatchObject({
      name: 'sysmon by host',
      query: 'source_type=windows_sysmon | stats count by device.hostname',
      description: 'Process launches across the fleet',
    });
  });

  it('sends no description when none was typed', async () => {
    await openSaveDialog();
    fireEvent.change(screen.getByPlaceholderText('e.g. Failed console logins'), { target: { value: 'no note' } });
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Save query' })); });

    await waitFor(() => expect(net.create).toHaveBeenCalledTimes(1));
    expect(net.create.mock.calls[0][0]).not.toHaveProperty('description');
  });
});

describe('Saved queries palette wiring (NAN-5695)', () => {
  it('passes edit and delete handlers that call the API and refresh the list', async () => {
    renderSearch();
    const edit = screen.getByRole('button', { name: 'Palette edit' });
    const del = screen.getByRole('button', { name: 'Palette delete' });
    expect((edit as HTMLButtonElement).disabled).toBe(false);
    expect((del as HTMLButtonElement).disabled).toBe(false);

    await act(async () => { fireEvent.click(edit); });
    await waitFor(() => expect(net.update).toHaveBeenCalledWith({
      id: 'ss_1',
      data: { name: 'renamed', query: 'user=root', description: '' },
    }));
    await waitFor(() => expect(net.refetchSaved).toHaveBeenCalledTimes(1));

    await act(async () => { fireEvent.click(del); });
    await waitFor(() => expect(net.remove).toHaveBeenCalledWith('ss_1'));
    await waitFor(() => expect(net.refetchSaved).toHaveBeenCalledTimes(2));
  });
});
