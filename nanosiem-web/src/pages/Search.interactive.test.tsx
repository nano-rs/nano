// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { useEffect } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { ComponentProps } from 'react';
import { Search } from './Search';

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
vi.mock('@/hooks/use-capabilities', () => ({ useCapabilities: () => ({ capabilities: {}, tenantPlan: mocks.tenantPlan }) }));
vi.mock('@/contexts/AuthContext', () => ({ useAuth: () => ({ user: {}, hasPermission: () => true, isAuthenticated: true }) }));
vi.mock('@/contexts/UserPreferencesContext', () => ({ useUserPreferences: () => ({ defaultTimeRange: '1h', queryMode: 'piped' }) }));
vi.mock('@/contexts/PageContext', () => ({ useHereCardOverride: () => {} }));
vi.mock('@/enterprise/contexts/NotebookContext', () => ({ useNotebookCapture: () => ({ captureSearch: mocks.noop }) }));
vi.mock('@/enterprise/hooks/use-melod-job', () => ({ useMelodJob: () => ({ loading: false }) }));
vi.mock('@/hooks/useSearchHistory', () => ({ useSearchHistory: () => ({ searchHistory: [], addToSearchHistory: mocks.history, refreshHistory: mocks.noop }) }));
vi.mock('@/hooks/use-mobile', () => ({ useIsMobile: () => false }));
vi.mock('@/components/search', () => ({
  FIELD_STATS_PINNED_COLUMNS: [],
  SearchQueryInput: ({ query, onQueryChange, onSearch }: { query: string; onQueryChange: (value: string) => void; onSearch: () => void }) => <>
    <input aria-label="Query" value={query} onChange={event => onQueryChange(event.target.value)} />
    <button onClick={() => onSearch()}>Run test search</button>
  </>,
  SearchResults: ({ results, displayType, onLoadMore, onPageChange, onVisibleRowsChange, totalCount, totalCountExact, prependedRowCount, isSearching, asyncJobId }: ComponentProps<typeof import('@/components/search')['SearchResults']>) => <>
    <div data-testid="results-pane" data-loading={String(!!((isSearching || asyncJobId) && results.length === 0))} />
    <div
      data-testid="rows"
      data-display={displayType}
      data-total={totalCount}
      data-exact={String(totalCountExact ?? true)}
      data-prepended={prependedRowCount ?? 0}
    >{JSON.stringify(results.map(row => row.fields))}</div>
    <button onClick={onLoadMore}>Load test page</button>
    <button onClick={() => onPageChange?.(1)}>Next test table page</button>
    <button onClick={() => onVisibleRowsChange?.(80, 40)}>Scroll test away from top</button>
  </>,
  FieldsPanel: (props: { query?: string; timeRange?: { start: string; end: string } }) => { mocks.panel(props); return null; },
  TimelineVisualization: ({ timelineData }: { timelineData: Array<{ events: number }> }) => {
    useEffect(() => {
      if (timelineData.some(bucket => bucket.events > 0)) mocks.noop('histogram-visible', timelineData);
    }, [timelineData]);
    return <div data-testid="timeline">{JSON.stringify(timelineData)}</div>;
  }, SavedQueriesPalette: () => null,
  SearchJobsModal: () => null, PrevalenceSlider: () => null, DatasetSelector: () => null,
}));
vi.mock('@/components/editor', () => ({ registerDynamicFields: () => {} }));
vi.mock('@/components/search/retro/useRetro', () => ({ primeDurableRetroResult: () => {} }));
vi.mock('@/enterprise/components/search/AnalyzeView', () => ({ AnalyzeView: () => null }));
vi.mock('@/components/reports/ScheduleReportDialog', () => ({ ScheduleReportDialog: () => null }));
vi.mock('@/components/dashboard', () => ({ AddToDashboardDialog: () => null }));
vi.mock('@/components/DemoHints', () => ({ SearchDemoHint: () => null }));
// NAN-2836: a stand-in picker that shows the page's range and lets a test pick one.
vi.mock('@/components/ui/date-time-range-picker', () => ({
  DateTimeRangePicker: ({ value, onChange, displayOverride }: { value: import('@/lib/time-range').TimeRangeValue; onChange: (v: import('@/lib/time-range').TimeRangeValue) => void; displayOverride?: string }) => <>
    <div data-testid="time-range">{value.type === 'preset' ? `preset:${value.preset}` : `custom:${value.start?.toISOString()}..${value.end?.toISOString()}`}</div>
    <div data-testid="time-range-label">{displayOverride ?? ''}</div>
    <button onClick={() => onChange({ type: 'preset', preset: 'Last 24 hours' })}>Pick last 24 hours</button>
    <button onClick={() => onChange({ type: 'custom', start: new Date('2026-09-20T00:00:00Z'), end: new Date('2026-09-20T06:00:00Z') })}>Pick absolute window</button>
  </>,
}));
vi.mock('@/components/search/SearchStatsBar', () => ({
  // Mirrors the real bar's NAN-2550 rendering: a count that is only a lower
  // bound is suffixed with `+`. Everything else about the bar is irrelevant here.
  SearchStatsBar: ({ totalCount, totalCountExact = true, firstRowsMs, completionMs, isSearching, asyncJobStatus, onCancel, timeWindow }: {
    totalCount: number; totalCountExact?: boolean; firstRowsMs?: number; completionMs?: number;
    isSearching?: boolean; asyncJobStatus?: string | null; onCancel?: () => void; timeWindow?: string;
  }) => <><div data-testid="hits">{totalCount}{totalCountExact ? '' : '+'}</div>
    <div data-testid="run-time-window">{timeWindow ?? ''}</div>
    <div data-testid="timing" data-first={firstRowsMs} data-complete={completionMs} />
    <div data-testid="search-state" data-searching={String(!!isSearching)} data-job-status={asyncJobStatus ?? ''} />
    {onCancel && <button onClick={onCancel}>Cancel test search</button>}</>,
}));

/** Every URL the page navigated to, so a tail tick's history push would show. */
const locations: string[] = [];
function LocationProbe() {
  const location = useLocation();
  useEffect(() => { locations.push(`${location.pathname}${location.search}`); }, [location]);
  return null;
}

function mount(query = 'actor.user.name="jsmith"', entry = '/search?prevalence=10&start=2026-09-21T14:20:00Z&end=2026-09-21T15:20:00Z') {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  client.setQueryData(['schema-fields'], mocks.schema);
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[entry]}><LocationProbe /><Search /></MemoryRouter></QueryClientProvider>);
  fireEvent.change(screen.getByLabelText('Query'), { target: { value: query } });
  return client;
}
beforeEach(() => {
  vi.clearAllMocks();
  locations.length = 0;
  localStorage.clear();
  sessionStorage.clear();
  // A hosted-shared tenant plan in its minimal contract shape (the parser
  // requires identity + components); no risk grant -> shared search surface.
  mocks.tenantPlan = { identity: { permissions: [] }, components: {} };
  mocks.fields.mockResolvedValue({ fields: [] });
  mocks.histogram.mockResolvedValue({ histogram: [] });
  mocks.stream.mockImplementation((_request, callbacks) => {
    const controller = new AbortController();
    queueMicrotask(() => callbacks.onError?.({ code: 'VALIDATION_ERROR', message: 'gen1 tenant' }));
    return controller;
  });
});
afterEach(cleanup);

it('renders hosted-shared interactive rows and requests matching field stats without creating a job', async () => {
  mocks.interactive.mockResolvedValue({ results: [{ 'actor.user.name': 'jsmith' }], total_count: 1, fields: [], execution_time_ms: 736, display_type: 'table' });
  mount();
  fireEvent.click(screen.getByText('Run test search'));
  await waitFor(() => expect(screen.getByTestId('rows').textContent).toContain('jsmith'));
  expect(screen.getByTestId('rows').getAttribute('data-display')).toBe('table');
  expect(mocks.interactive).toHaveBeenCalledOnce();
  const body = mocks.interactive.mock.calls[0][0];
  expect(body).not.toHaveProperty('async_mode');
  expect(body.query).toContain('where enrichments.data.host_count <= 10');
  expect(mocks.fields).toHaveBeenCalledWith(expect.objectContaining({ query: body.query, request_id: body.request_id, dataset: 'logs' }));
  expect(mocks.async).not.toHaveBeenCalled();
  expect(mocks.poll).not.toHaveBeenCalled();
  expect(mocks.legacy).not.toHaveBeenCalled();
});

it('renders an escalated artifact and appends a later page without resubmitting the job', async () => {
  const rows = Array.from({ length: 50 }, (_, uid) => ({ uid }));
  mocks.interactive.mockResolvedValueOnce({ job_id: 'server-escalation', status: 'queued' })
    .mockResolvedValue({ results: [{ uid: 50 }], total_count: 51, fields: [], execution_time_ms: 1 });
  mocks.poll.mockResolvedValue({ job_id: 'server-escalation', status: 'completed',
    durable_result: { rows: 50, pages: 2, page_rows: 25, has_more: true } });
  mocks.page.mockImplementation(async (_id, page) => ({ page, pages: 2, row_offset: page * 25, total_rows: 50, rows: rows.slice(page * 25, page * 25 + 25) }));
  mount();
  fireEvent.click(screen.getByText('Run test search'));
  await waitFor(() => expect(JSON.parse(screen.getByTestId('rows').textContent!)).toEqual(rows));
  fireEvent.click(screen.getByText('Load test page'));
  await waitFor(() => expect(JSON.parse(screen.getByTestId('rows').textContent!)).toEqual([...rows, { uid: 50 }]));
  expect(mocks.interactive).toHaveBeenCalledTimes(2);
  expect(mocks.interactive.mock.calls[1][0]).toMatchObject({ offset: 50, limit: 500 });
  expect(mocks.poll).toHaveBeenCalledExactlyOnceWith('server-escalation', expect.any(Object));
  expect(mocks.page.mock.calls).toEqual([['server-escalation', 0], ['server-escalation', 1]]);
  expect(mocks.async).not.toHaveBeenCalled();
});

it('NAN-3229: the stats-bar cancel stops a search whose request has not answered yet', async () => {
  let resolve!: (value: unknown) => void;
  mocks.interactive.mockImplementationOnce(() => new Promise(done => { resolve = done; }));
  mount();
  fireEvent.click(screen.getByText('Run test search'));
  await waitFor(() => expect(screen.getByTestId('search-state').getAttribute('data-searching')).toBe('true'));
  const requestId = mocks.interactive.mock.calls[0][0].request_id;
  fireEvent.click(screen.getByText('Cancel test search'));
  await waitFor(() => expect(mocks.cancel).toHaveBeenCalledWith(requestId));
  expect(screen.getByTestId('search-state').getAttribute('data-searching')).toBe('false');
  // The request then escalates at the server deadline: the late job is cancelled, never polled.
  resolve({ job_id: 'late-deadline-job', status: 'queued' });
  await waitFor(() => expect(mocks.cancelJob).toHaveBeenCalledWith('late-deadline-job'));
  expect(mocks.poll).not.toHaveBeenCalled();
});

it('NAN-3229: a deadline-escalated search shows its running job and the cancel stops it', async () => {
  mocks.interactive.mockResolvedValueOnce({ job_id: 'deadline-job', status: 'queued' });
  mocks.poll.mockResolvedValue({ job_id: 'deadline-job', status: 'running',
    progress: { percent: 40, rows_scanned: 4, rows_total: 10, elapsed_ms: 46_000 } });
  mount();
  fireEvent.click(screen.getByText('Run test search'));
  await waitFor(() => expect(screen.getByTestId('search-state').getAttribute('data-job-status')).toBe('running'));
  expect(screen.getByTestId('search-state').getAttribute('data-searching')).toBe('true');
  fireEvent.click(screen.getByText('Cancel test search'));
  await waitFor(() => expect(mocks.cancelJob).toHaveBeenCalledWith('deadline-job'));
  await waitFor(() => expect(screen.getByTestId('search-state').getAttribute('data-searching')).toBe('false'));
});

it('NAN-3883: a deadline-escalated search stays attached through a phase-only run and shows the result without a re-run', async () => {
  mocks.interactive.mockResolvedValueOnce({ job_id: 'long-30d', status: 'queued' });
  const running = { job_id: 'long-30d', status: 'running',
    progress: { phase: 'scanning', attempt: 1, rows_scanned: 0, rows_total: 0, percent: 0, elapsed_ms: 60_000 } };
  mocks.poll.mockResolvedValueOnce(running).mockResolvedValueOnce(running)
    .mockResolvedValueOnce({ ...running, progress: { ...running.progress, attempt: 2, elapsed_ms: 120_000 } })
    .mockResolvedValue({ job_id: 'long-30d', status: 'completed',
      durable_result: { rows: 2, pages: 1, page_rows: 25, has_more: false } });
  mocks.page.mockResolvedValue({ page: 0, pages: 1, row_offset: 0, total_rows: 2,
    rows: [{ 'metadata.log_source': 'windows_sysmon', count: 153_916_152 }, { 'metadata.log_source': 'okta', count: 5 }] });
  mount('* | stats count by metadata.log_source');
  fireEvent.click(screen.getByText('Run test search'));
  await waitFor(() => expect(screen.getByTestId('search-state').getAttribute('data-job-status')).toBe('running'));
  expect(screen.getByTestId('results-pane').getAttribute('data-loading')).toBe('true');
  await waitFor(() => expect(screen.getByTestId('rows').textContent).toContain('windows_sysmon'), { timeout: 8_000 });
  expect(screen.getByTestId('results-pane').getAttribute('data-loading')).toBe('false');
  // One submission; the job is followed, never re-run or re-submitted.
  expect(mocks.interactive).toHaveBeenCalledOnce();
  expect(mocks.async).not.toHaveBeenCalled();
  expect(mocks.cancelJob).not.toHaveBeenCalled();
  expect(mocks.poll.mock.calls.every(([id]) => id === 'long-30d')).toBe(true);
  expect(mocks.poll.mock.calls.length).toBeGreaterThanOrEqual(4);
}, 15_000);

it('NAN-3293: a failed durable job leaves the loading pane, shows its error, and a re-run retries', async () => {
  mocks.interactive.mockResolvedValueOnce({ job_id: 'baseline-job', status: 'queued' })
    .mockResolvedValueOnce({ results: [{ uid: 'retry' }], total_count: 1, fields: [], execution_time_ms: 1 });
  mocks.poll.mockResolvedValueOnce({ job_id: 'baseline-job', status: 'running', task_kind: 'baseline_v1' })
    .mockResolvedValue({ job_id: 'baseline-job', status: 'failed', task_kind: 'baseline_v1',
      error: 'platform enrichment authorization changed during execution' });
  mount('device.hostname="ws-it-083.corp.local" | baseline window=7d');
  fireEvent.click(screen.getByText('Run test search'));
  await waitFor(() => expect(screen.getByText(/platform enrichment authorization changed during execution/)).toBeTruthy());
  expect(screen.getByTestId('results-pane').getAttribute('data-loading')).toBe('false');
  expect(screen.getByTestId('search-state').getAttribute('data-searching')).toBe('false');
  expect(screen.getByTestId('search-state').getAttribute('data-job-status')).toBe('');
  expect(screen.getByRole('button', { name: /retry/i })).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: /retry/i }));
  await waitFor(() => expect(screen.getByTestId('rows').textContent).toContain('retry'));
  expect(mocks.interactive).toHaveBeenCalledTimes(2);
  expect(screen.queryByText(/platform enrichment authorization changed/)).toBeNull();
});

it('supersedes the old request, cancels its late job, and keeps the new rows', async () => {
  let resolve!: (value: unknown) => void;
  mocks.interactive.mockImplementationOnce(() => new Promise(done => { resolve = done; }))
    .mockResolvedValueOnce({ results: [{ user: 'new-user' }], total_count: 1, fields: [], execution_time_ms: 1 });
  mount();
  fireEvent.click(screen.getByText('Run test search'));
  const oldRequest = mocks.interactive.mock.calls[0][0].request_id;
  fireEvent.change(screen.getByLabelText('Query'), { target: { value: 'user="new-user"' } });
  fireEvent.click(screen.getByText('Run test search'));
  await waitFor(() => expect(screen.getByTestId('rows').textContent).toContain('new-user'));
  resolve({ job_id: 'stale-job', status: 'queued' });
  await waitFor(() => expect(mocks.cancelJob).toHaveBeenCalledWith('stale-job'));
  expect(mocks.cancel).toHaveBeenCalledWith(oldRequest);
  expect(mocks.poll).not.toHaveBeenCalled();
  expect(screen.getByTestId('rows').textContent).toContain('new-user');
});

it('keeps inline aggregate rows when the next table page escalates', async () => {
  const first = Array.from({ length: 50 }, (_, uid) => ({ uid }));
  const second = Array.from({ length: 50 }, (_, i) => ({ uid: i + 50 }));
  mocks.interactive.mockResolvedValueOnce({ results: first, total_count: 100, fields: [], execution_time_ms: 1, display_type: 'table' })
    .mockResolvedValueOnce({ job_id: 'table-page', status: 'queued' });
  mocks.poll.mockResolvedValue({ job_id: 'table-page', status: 'completed',
    durable_result: { rows: 50, pages: 1, page_rows: 50, has_more: false } });
  mocks.page.mockResolvedValue({ page: 0, pages: 1, row_offset: 0, total_rows: 50, rows: second });
  mount('actor.user.name="jsmith" | stats count by actor.user.name');
  fireEvent.click(screen.getByText('Run test search'));
  await waitFor(() => expect(JSON.parse(screen.getByTestId('rows').textContent!)).toEqual(first));
  expect(mocks.fields).not.toHaveBeenCalled();
  fireEvent.click(screen.getByText('Next test table page'));
  await waitFor(() => expect(JSON.parse(screen.getByTestId('rows').textContent!)).toEqual([...first, ...second]));
  expect(mocks.interactive).toHaveBeenCalledTimes(2);
  expect(mocks.interactive.mock.calls[1][0]).toMatchObject({ offset: 50, limit: 50, skip_histogram: true });
  expect(mocks.interactive.mock.calls[1][0].query).toContain('where enrichments.data.host_count <= 10 | stats');
  expect(mocks.poll).toHaveBeenCalledExactlyOnceWith('table-page', expect.any(Object));
  expect(mocks.page).toHaveBeenCalledExactlyOnceWith('table-page', 0);
  expect(mocks.legacy).not.toHaveBeenCalled();
});

// NAN-2550: "this count is only a lower bound" is no longer a warning banner —
// it is `total_count_exact` on the response, rendered inline as `N+` next to the
// count. A pre-NAN-2550 search service still pushes `LAKE_PAGE_BOUND_COUNT`, so
// the client filters that code out rather than showing a banner over a correct
// page (the NAN-2512/NAN-2514 symptom).
const legacyPageBoundSentinel = {
  severity: 'info', code: 'LAKE_PAGE_BOUND_COUNT',
  message: 'Exact hit-count metadata is still pending; more matching rows may exist.',
  impact: 'Visible rows are complete for this page.',
};
const pageBoundBanner = () => screen.queryByText(/Exact hit-count metadata is still pending/);
const hits = () => screen.getByTestId('hits').textContent;
const page = (offset: number) => Array.from({ length: 50 }, (_, i) => ({ uid: offset + i }));

// NAN-3093: page 1's timeline is its own request, so the rows paint first and
// the timeline's exact total lands when it answers, whichever comes second.
it('paints rows without waiting for the timeline and adopts its exact total', async () => {
  let answerHistogram: (value: unknown) => void = () => {};
  mocks.histogram.mockReturnValueOnce(new Promise(resolve => { answerHistogram = resolve; }));
  mocks.interactive.mockResolvedValueOnce({
    results: page(0), total_count: 51, total_count_exact: false,
    fields: [], execution_time_ms: 1, display_type: 'table',
  });
  mount();
  fireEvent.click(screen.getByText('Run test search'));
  await waitFor(() => expect(JSON.parse(screen.getByTestId('rows').textContent!)).toEqual(page(0)));
  const rowsBody = mocks.interactive.mock.calls[0][0];
  expect(rowsBody).toMatchObject({ offset: 0, skip_histogram: true });
  expect(mocks.histogram).toHaveBeenCalledOnce();
  expect(mocks.histogram.mock.calls[0][0]).toEqual({ query: rowsBody.query, time_range: rowsBody.time_range, dataset: rowsBody.dataset });
  expect(hits()).toBe('51+');
  expect(screen.getByTestId('timing').getAttribute('data-first')).not.toBeNull();
  expect(screen.getByTestId('timing').getAttribute('data-complete')).toBeNull();

  await act(async () => answerHistogram({ histogram: [{ time: '2026-09-21T14:00:00Z', count: 1234 }], total_count: 1234 }));
  await waitFor(() => expect(hits()).toBe('1234'));
  expect(Number(screen.getByTestId('timing').getAttribute('data-complete'))).toBeGreaterThanOrEqual(Number(screen.getByTestId('timing').getAttribute('data-first')));
  expect(mocks.noop.mock.calls.filter(call => call[0] === 'histogram-visible')).toHaveLength(1);

  // A page flip keeps the timeline's total and asks for no new timeline.
  mocks.interactive.mockResolvedValueOnce({
    results: page(50), total_count: 151, total_count_exact: false, fields: [], execution_time_ms: 1,
  });
  fireEvent.click(screen.getByText('Load test page'));
  await waitFor(() => expect(JSON.parse(screen.getByTestId('rows').textContent!)).toEqual([...page(0), ...page(50)]));
  expect(mocks.histogram).toHaveBeenCalledOnce();
  expect(hits()).toBe('1234');
});

it('keeps the timeline total when the rows answer after it', async () => {
  let answerRows: (value: unknown) => void = () => {};
  mocks.histogram.mockResolvedValueOnce({ histogram: [{ time: '2026-09-21T14:00:00Z', count: 7 }], total_count: 7 });
  mocks.interactive.mockReturnValueOnce(new Promise(resolve => { answerRows = resolve; }));
  mount();
  fireEvent.click(screen.getByText('Run test search'));
  await waitFor(() => expect(mocks.histogram).toHaveBeenCalledOnce());
  await act(async () => {});
  expect(mocks.noop.mock.calls.filter(call => call[0] === 'histogram-visible')).toHaveLength(0);
  await act(async () => answerRows({
    results: page(0).slice(0, 7), total_count: 7, total_count_exact: false,
    fields: [], execution_time_ms: 1, display_type: 'table',
  }));
  await waitFor(() => expect(JSON.parse(screen.getByTestId('rows').textContent!)).toHaveLength(7));
  expect(hits()).toBe('7');
  expect(mocks.noop.mock.calls.filter(call => call[0] === 'histogram-visible')).toHaveLength(1);
  expect(mocks.histogram).toHaveBeenCalledOnce();
});

it('keeps a resolved exact count free of the lower-bound marker while paging', async () => {
  // Page 1 resolved an exact count (its histogram companion ran).
  mocks.interactive.mockResolvedValueOnce({
    results: page(0), total_count: 1000, total_count_exact: true,
    fields: [], execution_time_ms: 1, display_type: 'table',
    histogram: [{ time: '2026-09-21T14:00:00Z', count: 1000 }],
  })
    // Load more: offset > 0 skips the histogram, so this page reports only its
    // own bound — and an old server would additionally push the sentinel.
    .mockResolvedValueOnce({
      results: page(50), total_count: 1100, total_count_exact: false,
      fields: [], execution_time_ms: 1, warnings: [legacyPageBoundSentinel],
    })
    // A fresh run that resolves the count again stays exact.
    .mockResolvedValueOnce({
      results: page(0), total_count: 1000, total_count_exact: true,
      fields: [], execution_time_ms: 1, display_type: 'table',
      histogram: [{ time: '2026-09-21T14:00:00Z', count: 1000 }],
    });

  mount();
  fireEvent.click(screen.getByText('Run test search'));
  await waitFor(() => expect(JSON.parse(screen.getByTestId('rows').textContent!)).toEqual(page(0)));
  expect(hits()).toBe('1000');
  expect(pageBoundBanner()).toBeNull();

  fireEvent.click(screen.getByText('Load test page'));
  await waitFor(() => expect(JSON.parse(screen.getByTestId('rows').textContent!)).toEqual([...page(0), ...page(50)]));
  expect(mocks.interactive.mock.calls[1][0]).toMatchObject({ offset: 50, skip_histogram: true });
  // The appended page's own bound must not demote the resolved search-wide count…
  expect(hits()).toBe('1000');
  // …and the legacy sentinel must not reach the drawer.
  expect(pageBoundBanner()).toBeNull();

  fireEvent.click(screen.getByText('Run test search'));
  await waitFor(() => expect(mocks.interactive).toHaveBeenCalledTimes(3));
  await waitFor(() => expect(JSON.parse(screen.getByTestId('rows').textContent!)).toEqual(page(0)));
  expect(hits()).toBe('1000');
  expect(pageBoundBanner()).toBeNull();
});

it('reports an exact empty result as 0, not as a lower bound', async () => {
  // A zero count is only a fallback estimate when the page came back FULL; a
  // genuinely empty result set is exact and must not render "0+".
  mocks.interactive.mockResolvedValueOnce({
    results: [], total_count: 0, total_count_exact: true,
    fields: [], execution_time_ms: 1, display_type: 'table',
  });
  mount();
  fireEvent.click(screen.getByText('Run test search'));
  await waitFor(() => expect(hits()).toBe('0'));
});

it('renders a count the backend could not resolve as a lower bound, not a banner', async () => {
  mocks.interactive.mockResolvedValueOnce({
    results: page(0), total_count: 50, total_count_exact: false,
    fields: [], execution_time_ms: 1, display_type: 'table',
    warnings: [
      legacyPageBoundSentinel,
      // Any genuinely `info` warning: severity drives the drawer glyph, and it
      // was unset on this path before the NAN-2512/NAN-2514 follow-up.
      { severity: 'info', code: 'LAKE_EVENTS_INCOMPLETE', message: 'Some shards were slow to answer.' },
    ],
  });
  mount();
  fireEvent.click(screen.getByText('Run test search'));
  await waitFor(() => expect(hits()).toBe('50+'));
  expect(pageBoundBanner()).toBeNull();
  expect(screen.getByText('Some shards were slow to answer.')).toBeTruthy();
  // `info` severity, so the drawer shows the Info glyph, not the amber warning one.
  expect(screen.getByTitle('Info')).toBeTruthy();
});

// NAN-2551 — the tail is a prepend, not a re-run.

it('follows a lean cell stream, deduplicates merged parts, and cancels on stop', async () => {
  let callbacks!: import('@/lib/api/types').SearchStreamCallbacks;
  const controller = new AbortController();
  mocks.stream.mockImplementation((_request, handlers) => { callbacks = handlers; return controller; });
  await mountTailed(paged(2));
  fireEvent.click(screen.getByText('tail -f'));
  await waitFor(() => expect(mocks.stream).toHaveBeenCalledOnce());
  expect(mocks.stream.mock.calls[0][2]).toEqual({ follow: true });
  expect(mocks.stream.mock.calls[0][0]).toMatchObject({ dataset: 'logs', offset: 0 });
  act(() => callbacks.onRows?.({ rows: [
    { 'metadata.uid': 'new-1', seq: 1 },
    { 'metadata.uid': 'paged-0', seq: 0 },
  ], batch_index: 0, cumulative_count: 2 }));
  await waitFor(() => expect(uids()).toEqual(['new-1', 'paged-0', 'paged-1']));
  act(() => callbacks.onRows?.({ rows: [{ 'metadata.uid': 'new-1', seq: 1 }], batch_index: 1, cumulative_count: 3 }));
  expect(uids()).toEqual(['new-1', 'paged-0', 'paged-1']);
  expect(mocks.legacy).not.toHaveBeenCalled();
  fireEvent.click(screen.getByText('tail -f'));
  expect(controller.signal.aborted).toBe(true);
});

it('falls back to polling the moment lean follow fails, then reconnects it with a fresh window (NAN-3244)', async () => {
  const controllers: AbortController[] = [];
  const handlers: import('@/lib/api/types').SearchStreamCallbacks[] = [];
  mocks.stream.mockImplementation((_request, callbacks) => {
    const controller = new AbortController();
    controllers.push(controller);
    handlers.push(callbacks);
    return controller;
  });
  await mountTailed(paged(1));
  vi.useFakeTimers({ shouldAdvanceTime: true });
  try {
    fireEvent.click(screen.getByText('tail -f'));
    expect(mocks.stream).toHaveBeenCalledTimes(1);
    const firstStart = Date.parse(mocks.stream.mock.calls[0][0].time_range.start);
    act(() => handlers[0].onStarted?.({ job_id: 'j', query_id: 'q', is_streaming: true }));
    act(() => handlers[0].onRows?.({ rows: [{ 'metadata.uid': 'follow-1', seq: 5 }], batch_index: 0, cumulative_count: 1 }));
    await waitFor(() => expect(uids()).toEqual(['follow-1', 'paged-0']));

    // While the follow is open, ticks do not poll.
    await act(async () => { await vi.advanceTimersByTimeAsync(30_000); });
    expect(mocks.legacy).not.toHaveBeenCalled();

    // The live failure: the server ends the stream with RESOURCE_EXHAUSTED.
    mocks.legacy.mockResolvedValue({ results: [{ 'metadata.uid': 'poll-1', seq: 6, time: new Date().toISOString() }],
      total_count: 1, fields: [], execution_time_ms: 1 });
    act(() => handlers[0].onError?.({ code: 'RESOURCE_EXHAUSTED', message: 'Interactive query exhausted its memory budget' }));
    // A poll goes out at once and its arrival is prepended.
    await waitFor(() => expect(mocks.legacy).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(uids()).toEqual(['poll-1', 'follow-1', 'paged-0']));

    // Polling continues every interval and the follow is reconnected after
    // the backoff with a window re-anchored at now.
    await act(async () => { await vi.advanceTimersByTimeAsync(15_000); });
    expect(mocks.legacy.mock.calls.length).toBeGreaterThanOrEqual(2);
    expect(mocks.stream).toHaveBeenCalledTimes(2);
    expect(controllers[0].signal.aborted).toBe(true);
    const secondStart = Date.parse(mocks.stream.mock.calls[1][0].time_range.start);
    expect(secondStart).toBeGreaterThanOrEqual(firstStart + 45_000);
    expect(uids().filter((uid: string) => uid === 'poll-1')).toHaveLength(1);
  } finally {
    vi.useRealTimers();
  }
});

it('a follow that goes silent is detected as stalled, polled from its last row, and reconnected (NAN-3264)', async () => {
  const controllers: AbortController[] = [];
  const handlers: import('@/lib/api/types').SearchStreamCallbacks[] = [];
  mocks.stream.mockImplementation((_request, callbacks) => {
    const controller = new AbortController();
    controllers.push(controller);
    handlers.push(callbacks);
    return controller;
  });
  await mountTailed(paged(1));
  vi.useFakeTimers({ shouldAdvanceTime: true });
  try {
    fireEvent.click(screen.getByText('tail -f'));
    expect(mocks.stream).toHaveBeenCalledTimes(1);
    act(() => handlers[0].onStarted?.({ job_id: 'j', query_id: 'q', is_streaming: true }));
    const followTime = new Date(Date.now() - 5_000).toISOString();
    act(() => handlers[0].onRows?.({ rows: [{ 'metadata.uid': 'follow-1', time: followTime }], batch_index: 0, cumulative_count: 1 }));
    await waitFor(() => expect(uids()).toEqual(['follow-1', 'paged-0']));

    // Heartbeats alone keep a quiet follow alive well past the stall window.
    for (let i = 0; i < 9; i++) {
      await act(async () => { await vi.advanceTimersByTimeAsync(10_000); });
      act(() => handlers[0].onHeartbeat?.({ delivered: 1 }));
    }
    expect(mocks.legacy).not.toHaveBeenCalled();
    expect(controllers[0].signal.aborted).toBe(false);

    // Then it wedges: the connection stays open but nothing arrives. The
    // stall watchdog ends it and polls at once, from the follow's last row.
    mocks.legacy.mockResolvedValue({ results: [{ 'metadata.uid': 'poll-1', time: new Date().toISOString() }],
      total_count: 1, fields: [], execution_time_ms: 1 });
    await act(async () => { await vi.advanceTimersByTimeAsync(50_000); });
    expect(controllers[0].signal.aborted).toBe(true);
    await waitFor(() => expect(mocks.legacy).toHaveBeenCalled());
    const pollStart = Date.parse(mocks.legacy.mock.calls[0][0].time_range.start);
    expect(pollStart).toBe(Date.parse(followTime) - 120_000);
    await waitFor(() => expect(uids()).toEqual(['poll-1', 'follow-1', 'paged-0']));

    // The follow is reconnected after the backoff.
    await act(async () => { await vi.advanceTimersByTimeAsync(20_000); });
    expect(mocks.stream).toHaveBeenCalledTimes(2);
  } finally {
    vi.useRealTimers();
  }
});

it('a follow the server refuses as unsupported polls without reconnecting', async () => {
  await mountTailed(paged(1));
  vi.useFakeTimers({ shouldAdvanceTime: true });
  try {
    mocks.legacy.mockResolvedValue({ results: [], total_count: 0, fields: [], execution_time_ms: 1 });
    fireEvent.click(screen.getByText('tail -f'));
    await act(async () => { await vi.advanceTimersByTimeAsync(5 * 60_000); });
    expect(mocks.stream).toHaveBeenCalledTimes(1);
    expect(mocks.legacy.mock.calls.length).toBeGreaterThanOrEqual(20);
  } finally {
    vi.useRealTimers();
  }
});

/** Rows the paged search already put on screen, oldest last (newest-first list). */
const paged = (count: number, from = 0) =>
  Array.from({ length: count }, (_, i) => ({ 'metadata.uid': `paged-${from + i}`, seq: from + i }));

/**
 * Arm an escalated artifact search over `rows`, then run it. Each artifact
 * chunk is served as its own job (`job@offset@limit`), the way the durable
 * service does — the first chunk is the UI page, later chunks the 500-row
 * batches NAN-2514 prefetches.
 */
async function mountTailed(rows: Array<Record<string, unknown>>, pageRows = 250) {
  const chunkOf = (jobId: string) => {
    const [, offset, limit] = jobId.split('@').map(Number);
    return { offset, rows: rows.slice(offset, offset + limit) };
  };
  mocks.interactive.mockImplementation(async (body: { offset: number; limit: number }) =>
    ({ job_id: `job@${body.offset}@${body.limit}`, status: 'queued' }));
  mocks.poll.mockImplementation(async (jobId: string) => {
    const chunk = chunkOf(jobId);
    return { job_id: jobId, status: 'completed', durable_result: {
      rows: chunk.rows.length,
      pages: Math.max(1, Math.ceil(chunk.rows.length / pageRows)),
      page_rows: pageRows,
      has_more: chunk.offset + chunk.rows.length < rows.length,
    } };
  });
  mocks.page.mockImplementation(async (jobId: string, page: number) => {
    const chunk = chunkOf(jobId);
    return { page, pages: Math.max(1, Math.ceil(chunk.rows.length / pageRows)), row_offset: page * pageRows,
      total_rows: chunk.rows.length, rows: chunk.rows.slice(page * pageRows, (page + 1) * pageRows) };
  });
  mount();
  fireEvent.click(screen.getByText('Run test search'));
  await waitFor(() => expect(JSON.parse(screen.getByTestId('rows').textContent!)).toHaveLength(Math.min(rows.length, 50)));
}

/** Infinite-scroll until `target` rows are on screen (50 per page). */
async function scrollTo(target: number) {
  for (let shown = 50; shown < target; shown += 50) {
    fireEvent.click(screen.getByText('Load test page'));
    await waitFor(() => expect(JSON.parse(screen.getByTestId('rows').textContent!)).toHaveLength(shown + 50));
  }
}

/**
 * Fire `ticks` live-tail intervals and let everything they start settle,
 * without asserting *how* the tick refreshed. The assertions that follow are
 * then the ones that fail when a tick re-runs the search instead of prepending.
 */
async function settleTicks(ticks: number, arrivals: (tick: number) => Array<Record<string, unknown>>) {
  for (let t = 0; t < ticks; t++) {
    mocks.legacy.mockResolvedValueOnce({ results: arrivals(t), total_count: arrivals(t).length, fields: [], execution_time_ms: 1 });
    await act(async () => { await vi.advanceTimersByTimeAsync(15_000); });
    await act(async () => { await vi.advanceTimersByTimeAsync(2_000); });
  }
}

/** Fire `ticks` live-tail intervals, each answered with `arrivals(tick)`. */
async function tick(ticks: number, arrivals: (tick: number) => Array<Record<string, unknown>>) {
  for (let t = 0; t < ticks; t++) {
    mocks.legacy.mockResolvedValueOnce({ results: arrivals(t), total_count: arrivals(t).length, fields: [], execution_time_ms: 1 });
    const before = mocks.legacy.mock.calls.length;
    await vi.advanceTimersByTimeAsync(15_000);
    await waitFor(() => expect(mocks.legacy.mock.calls.length).toBeGreaterThan(before));
  }
}

it('keeps every scrolled row across tail ticks, and rebuilds neither the artifact nor the URL, history or AI context', async () => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  try {
    // 500 rows already materialised and scrolled through (NAN-2514 artifact).
    const rows = paged(500);
    await mountTailed(rows);
    await scrollTo(500);

    const searchCalls = mocks.interactive.mock.calls.length;
    const pollCalls = mocks.poll.mock.calls.length;
    const pageCalls = mocks.page.mock.calls.length;
    const historyCalls = mocks.history.mock.calls.length;
    const urlUpdates = locations.length;

    fireEvent.click(screen.getByText('tail -f'));
    await settleTicks(4, t => [{ 'metadata.uid': `new-${t}`, seq: 1000 + t, time: `2026-09-21T15:2${t}:00Z` }]);

    // The scrolled result set is intact, with the arrivals in front of it.
    const shown = JSON.parse(screen.getByTestId('rows').textContent!);
    expect(shown).toHaveLength(504);
    expect(shown.slice(4)).toEqual(rows);
    expect(shown.slice(0, 4).map((row: { 'metadata.uid': string }) => row['metadata.uid']))
      .toEqual(['new-3', 'new-2', 'new-1', 'new-0']);

    // The artifact was never re-submitted, re-polled or re-read: no `handleSearch`
    // re-entry, so nothing in its `!append` reset block ran — which is also what
    // keeps the AI refinement conversation, a dismissed limit warning, the
    // histogram and the page-1 count alive across a tick.
    expect(mocks.interactive).toHaveBeenCalledTimes(searchCalls);
    expect(mocks.poll).toHaveBeenCalledTimes(pollCalls);
    expect(mocks.page).toHaveBeenCalledTimes(pageCalls);
    expect(mocks.async).not.toHaveBeenCalled();
    // No browser-history entry and no recent-search entry per tick.
    expect(locations).toHaveLength(urlUpdates);
    expect(mocks.history).toHaveBeenCalledTimes(historyCalls);
  } finally {
    vi.useRealTimers();
  }
});

it('asks for an overlapping window, skips the histogram, and prepends each arrival once', async () => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  try {
    await mountTailed(paged(2));
    fireEvent.click(screen.getByText('tail -f'));

    const arrival = { 'metadata.uid': 'new-a', seq: 9, time: '2026-09-21T15:25:00Z' };
    // The same event comes back on the next tick — the overlap is deliberate.
    await tick(3, () => [arrival]);

    const body = mocks.legacy.mock.calls[0][0];
    expect(body).toMatchObject({ limit: 500, offset: 0, skip_histogram: true, skip_field_stats: true, table_view: true });
    expect(body.query).toContain('where enrichments.data.host_count <= 10');
    const asked = Date.parse(body.time_range.end) - Date.parse(body.time_range.start);
    expect(asked).toBeGreaterThanOrEqual(120_000);

    const shown = JSON.parse(screen.getByTestId('rows').textContent!);
    expect(shown.filter((row: { 'metadata.uid': string }) => row['metadata.uid'] === 'new-a')).toHaveLength(1);
    expect(shown).toHaveLength(3);
  } finally {
    vi.useRealTimers();
  }
});

it('holds arrivals behind an "N new events" chip while the analyst has scrolled away', async () => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  try {
    await mountTailed(paged(3));
    fireEvent.click(screen.getByText('tail -f'));
    fireEvent.click(screen.getByText('Scroll test away from top'));

    await tick(2, t => [{ 'metadata.uid': `held-${t}`, seq: t, time: `2026-09-21T15:3${t}:00Z` }]);

    // Nothing moved under the analyst's viewport.
    expect(JSON.parse(screen.getByTestId('rows').textContent!)).toHaveLength(3);
    const chip = await screen.findByText('new events');
    expect(chip.parentElement!.textContent).toContain('2');

    fireEvent.click(chip);
    await waitFor(() => expect(JSON.parse(screen.getByTestId('rows').textContent!)).toHaveLength(5));
    expect(screen.queryByText('new events')).toBeNull();
  } finally {
    vi.useRealTimers();
  }
});

it('tells the results list how many rows are prepended, so a lower-bound count cannot page an empty search', async () => {
  // NAN-2550 x NAN-2551. `hasMore` keeps loading while the count is only a
  // lower bound. Tail arrivals are prepended into `results` AND summed into
  // `totalCount`, so without `prependedRowCount` the first arrival on a query
  // that matches nothing would look like "a paged row exists, fetch page 2".
  vi.useFakeTimers({ shouldAdvanceTime: true });
  try {
    mocks.interactive.mockResolvedValue({
      results: [], total_count: 0, total_count_exact: false, fields: [], execution_time_ms: 1,
    });
    mount();
    fireEvent.click(screen.getByText('Run test search'));
    await waitFor(() => expect(screen.getByTestId('rows').textContent).toBe('[]'));
    const rows = () => screen.getByTestId('rows');
    expect(rows().getAttribute('data-exact')).toBe('false');
    expect(rows().getAttribute('data-prepended')).toBe('0');

    fireEvent.click(screen.getByText('tail -f'));
    await tick(1, () => [
      { 'metadata.uid': 'arrival-0', seq: 0, time: '2026-09-21T15:25:00Z' },
      { 'metadata.uid': 'arrival-1', seq: 1, time: '2026-09-21T15:26:00Z' },
    ]);
    await waitFor(() => expect(JSON.parse(rows().textContent!)).toHaveLength(2));

    // Both rows on screen are tail arrivals and both are inside the summed
    // total, so the paged set the lower bound describes is still empty.
    expect(rows().getAttribute('data-prepended')).toBe('2');
    expect(rows().getAttribute('data-total')).toBe('2');
    expect(JSON.parse(rows().textContent!).length - Number(rows().getAttribute('data-prepended'))).toBe(0);
  } finally {
    vi.useRealTimers();
  }
});

// NAN-2557 — three residuals of the NAN-2551 tail.

const uids = () => JSON.parse(screen.getByTestId('rows').textContent!)
  .map((row: { 'metadata.uid': string }) => row['metadata.uid']);

/** A plain interactive result set — no artifact, events view, so the tail prepends. */
function mountPaged(rows: Array<Record<string, unknown>>, exact = true) {
  mocks.interactive.mockResolvedValue({
    results: rows, total_count: rows.length, total_count_exact: exact,
    fields: [], execution_time_ms: 1,
  });
  mount();
  fireEvent.click(screen.getByText('Run test search'));
  return waitFor(() => expect(uids()).toHaveLength(rows.length));
}

it('drops a tail tick that lands after a new search superseded it', async () => {
  // The tick awaits `/api/search`. A fresh search started meanwhile resets the
  // tail's seen-key set and replaces the result set, so a late tick that does
  // not re-check the request id seeds the NEW query's dedupe set with the OLD
  // query's keys and prepends the old query's rows.
  vi.useFakeTimers({ shouldAdvanceTime: true });
  try {
    await mountPaged(paged(2));
    fireEvent.click(screen.getByText('tail -f'));

    let land!: (value: unknown) => void;
    mocks.legacy.mockImplementationOnce(() => new Promise(done => { land = done; }));
    await vi.advanceTimersByTimeAsync(15_000);
    await waitFor(() => expect(mocks.legacy).toHaveBeenCalledTimes(1));

    mocks.interactive.mockResolvedValue({
      results: [{ 'metadata.uid': 'other-0', seq: 0 }], total_count: 1, total_count_exact: true,
      fields: [], execution_time_ms: 1,
    });
    fireEvent.change(screen.getByLabelText('Query'), { target: { value: 'actor.user.name="other"' } });
    fireEvent.click(screen.getByText('Run test search'));
    await waitFor(() => expect(uids()).toEqual(['other-0']));

    await act(async () => {
      land({
        results: [{ 'metadata.uid': 'stale-0', seq: 99, time: '2026-09-21T15:25:00Z' }],
        total_count: 1, fields: [], execution_time_ms: 1,
      });
      await vi.advanceTimersByTimeAsync(0);
    });

    // The superseded tick's rows belong to the previous search: none of them land.
    expect(uids()).toEqual(['other-0']);
    expect(screen.getByTestId('rows').getAttribute('data-prepended')).toBe('0');
  } finally {
    vi.useRealTimers();
  }
});

it('keeps prepended arrivals across a re-arm and does not deliver them twice', async () => {
  // Re-arming (tail off/on, or an interval change) zeroes the watermark. The
  // rows already prepended stay on screen — an analyst re-arming is not asking
  // for them to be thrown away — so the re-arm must also keep their keys, or
  // the next tick's deliberate overlap prepends them a second time.
  vi.useFakeTimers({ shouldAdvanceTime: true });
  try {
    await mountPaged(paged(2));
    fireEvent.click(screen.getByText('tail -f'));

    const arrival = { 'metadata.uid': 'new-a', seq: 9, time: '2026-09-21T15:25:00Z' };
    await tick(1, () => [arrival]);
    await waitFor(() => expect(uids()).toEqual(['new-a', 'paged-0', 'paged-1']));

    fireEvent.click(screen.getByText('tail -f'));
    fireEvent.click(screen.getByText('tail -f'));
    // Nothing was thrown away by the re-arm itself.
    expect(uids()).toEqual(['new-a', 'paged-0', 'paged-1']);

    await tick(1, () => [arrival]);
    expect(uids()).toEqual(['new-a', 'paged-0', 'paged-1']);
    expect(screen.getByTestId('rows').getAttribute('data-prepended')).toBe('1');
  } finally {
    vi.useRealTimers();
  }
});

it('reports one total for the set on screen once the tail has prepended arrivals', async () => {
  // NAN-2557: the results list was summed and the footer was not, so the page
  // showed two different totals for one result set.
  vi.useFakeTimers({ shouldAdvanceTime: true });
  try {
    await mountPaged(paged(3));
    expect(hits()).toBe('3');

    fireEvent.click(screen.getByText('tail -f'));
    await tick(1, () => [
      { 'metadata.uid': 'arrival-0', seq: 0, time: '2026-09-21T15:25:00Z' },
      { 'metadata.uid': 'arrival-1', seq: 1, time: '2026-09-21T15:26:00Z' },
    ]);
    await waitFor(() => expect(uids()).toHaveLength(5));

    expect(screen.getByTestId('rows').getAttribute('data-total')).toBe('5');
    expect(hits()).toBe('5');
    // …and the NAN-2550 split still holds: the paged set is what the count's
    // exactness describes.
    expect(screen.getByTestId('rows').getAttribute('data-prepended')).toBe('2');
  } finally {
    vi.useRealTimers();
  }
});

// NAN-2836 — a time range picked while tailing must stick.

const range = () => screen.getByTestId('time-range').textContent!;
const tailChip = () => screen.getByText('tail -f').closest('div')!;
const tailing = () => tailChip().className.includes('emerald');

/** An aggregate: its tail tick is a whole-window re-run, which rewrites the page's range. */
async function mountAggregateTail() {
  mocks.interactive.mockResolvedValue({ results: [{ c: 1 }], total_count: 1, fields: [], execution_time_ms: 1, display_type: 'table' });
  mount('actor.user.name="jsmith" | stats count by actor.user.name');
  fireEvent.click(screen.getByText('Run test search'));
  await waitFor(() => expect(screen.getByTestId('rows').textContent).toContain('"c":1'));
  fireEvent.click(screen.getByText('tail -f'));
  await settleTicks(1, () => []);
  expect(tailing()).toBe(true);
}

it('keeps tailing on the new window when a relative range is picked', async () => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  try {
    await mountAggregateTail();
    fireEvent.click(screen.getByText('Pick last 24 hours'));
    await settleTicks(3, () => []);

    // Still tailing, and every tick since the pick asked for a 24h window.
    expect(tailing()).toBe(true);
    // NAN-3299: the pick stays relative — a run no longer rewrites it to
    // the fixed bounds it resolved (that rewrite re-ran the search).
    expect(range()).toBe('preset:Last 24 hours');
    const last = mocks.interactive.mock.calls.at(-1)![0].time_range;
    expect(Date.parse(last.end) - Date.parse(last.start)).toBe(24 * 3600_000);
    expect(locations.at(-1)).not.toContain('start=2026-09-21T14');
  } finally {
    vi.useRealTimers();
  }
});

it('stops the tail, and keeps the pick, when a fixed past range is picked', async () => {
  // Before the fix the tail stayed on and its next tick re-anchored the
  // picked window at "now": the analyst's range was silently replaced.
  vi.useFakeTimers({ shouldAdvanceTime: true });
  try {
    await mountAggregateTail();
    fireEvent.click(screen.getByText('Pick absolute window'));
    await act(async () => { await vi.advanceTimersByTimeAsync(500); });
    const searches = mocks.interactive.mock.calls.length;
    await settleTicks(3, () => []);

    expect(range()).toBe('custom:2026-09-20T00:00:00.000Z..2026-09-20T06:00:00.000Z');
    expect(tailing()).toBe(false);
    expect(screen.getByText('tail stopped · fixed range')).toBeTruthy();
    expect(mocks.interactive).toHaveBeenCalledTimes(searches);
    expect(locations.at(-1)).toContain('start=2026-09-20T00%3A00%3A00.000Z');

    // Turning the tail back on clears the notice.
    fireEvent.click(screen.getByText('tail -f'));
    expect(screen.queryByText('tail stopped · fixed range')).toBeNull();
  } finally {
    vi.useRealTimers();
  }
});

it('keeps a relative range picked while tailing an event list', async () => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  try {
    await mountPaged(paged(2));
    fireEvent.click(screen.getByText('tail -f'));
    await tick(1, () => []);
    fireEvent.click(screen.getByText('Pick last 24 hours'));
    await settleTicks(3, () => []);

    expect(tailing()).toBe(true);
    // NAN-3299: the pick stays relative — a run no longer rewrites it to
    // the fixed bounds it resolved (that rewrite re-ran the search).
    expect(range()).toBe('preset:Last 24 hours');
    expect(locations.at(-1)).not.toContain('start=2026-09-21T14');
  } finally {
    vi.useRealTimers();
  }
});

it('ignores a superseded histogram that resolves after the new rows', async () => {
  let answerOldHistogram!: (value: unknown) => void;
  mocks.histogram.mockReturnValueOnce(new Promise(resolve => { answerOldHistogram = resolve; }))
    .mockResolvedValueOnce({ histogram: [{ time: '2026-09-21T14:00:00Z', count: 7 }], total_count: 7 });
  mocks.interactive.mockResolvedValueOnce({ results: [{ uid: 'old' }], total_count: 51, fields: [], execution_time_ms: 1 })
    .mockResolvedValueOnce({ results: [{ uid: 'new' }], total_count: 1, fields: [], execution_time_ms: 1 });
  mount();
  fireEvent.click(screen.getByText('Run test search'));
  await waitFor(() => expect(screen.getByTestId('rows').textContent).toContain('old'));
  fireEvent.change(screen.getByLabelText('Query'), { target: { value: 'user="new"' } });
  fireEvent.click(screen.getByText('Run test search'));
  await waitFor(() => expect(hits()).toBe('7'));
  await act(async () => answerOldHistogram({ histogram: [{ time: '2026-09-21T14:00:00Z', count: 999 }], total_count: 999 }));
  expect(hits()).toBe('7');
  expect(screen.getByTestId('rows').textContent).toContain('new');
  expect(JSON.parse(screen.getByTestId('timeline').textContent!).map((bucket: { events: number }) => bucket.events)).toEqual([7]);
  expect(mocks.histogram).toHaveBeenCalledTimes(2);
});

it('keeps paging a rows-first count until the API proves exhaustion', async () => {
  let answerHistogram: (value: unknown) => void = () => {};
  mocks.histogram.mockReturnValueOnce(new Promise(resolve => { answerHistogram = resolve; }));
  mocks.interactive.mockResolvedValueOnce({ results: page(0), total_count: 50, total_count_exact: false,
    has_more: true, next_offset: 50, fields: [], execution_time_ms: 1 });
  mount();
  fireEvent.click(screen.getByText('Run test search'));
  await waitFor(() => expect(hits()).toBe('50+'));
  await act(async () => answerHistogram({ histogram: [], total_count: 50 }));
  await waitFor(() => expect(hits()).toBe('50'));
  mocks.interactive.mockResolvedValueOnce({ results: page(50), total_count: 100, total_count_exact: false,
    has_more: true, next_offset: 100, fields: [], execution_time_ms: 1 });
  fireEvent.click(screen.getByText('Load test page'));
  await waitFor(() => expect(mocks.interactive).toHaveBeenCalledTimes(2));
  await waitFor(() => expect(JSON.parse(screen.getByTestId('rows').textContent!)).toHaveLength(100));
  mocks.interactive.mockResolvedValueOnce({ results: page(100).slice(0, 7), total_count: 107, total_count_exact: false,
    has_more: false, next_offset: null, fields: [], execution_time_ms: 1 });
  fireEvent.click(screen.getByText('Load test page'));
  await waitFor(() => expect(JSON.parse(screen.getByTestId('rows').textContent!)).toHaveLength(107));
  fireEvent.click(screen.getByText('Load test page'));
  expect(mocks.interactive).toHaveBeenCalledTimes(3);
  expect(mocks.interactive.mock.calls.map(call => call[0].offset)).toEqual([0, 50, 100]);
});

it('restores a typed Lateral artifact with its incident range instead of the identity lookback', async () => {
  const start = '2026-09-20T00:00:00Z';
  const end = '2026-09-21T00:00:00Z';
  const query = 'device.hostname="h0" | lateral';
  const graph = { nodes: [], edges: [], summary: { seed: { id: 'h0', kind: 'host' }, maxHops: 4 } };
  mocks.interactive.mockResolvedValue({ job_id: 'lateral-restored', status: 'queued' });
  mocks.poll.mockResolvedValue({ job_id: 'lateral-restored', status: 'completed', task_kind: 'lateral_v1', query,
    start: '2026-08-21T00:00:00Z', end, durable_result: { rows: 1, pages: 1, page_rows: 1, has_more: false } });
  mocks.page.mockResolvedValue({ page: 0, pages: 1, total_rows: 1, rows: [{ operation: 'lateral', response: {
    results: [{ _display_type: 'lateral', _lateral_graph: graph, _lateral_time_range: { start, end } }],
    total_count: 0, total_count_exact: true, execution_time_ms: 1, fields: [], display_type: 'lateral',
  } }] });
  mount('', '/search?job_id=lateral-restored');
  await waitFor(() => { expect(mocks.poll).toHaveBeenCalled(); }, { timeout: 4000 });
  await waitFor(() => expect(screen.getByTestId('time-range').textContent).toContain('2026-09-20'), { timeout: 4000 });
  await waitFor(() => expect(screen.getByTestId('rows').getAttribute('data-display')).toBe('lateral'), { timeout: 4000 });
  expect(screen.getByTestId('time-range').textContent).toBe('custom:2026-09-20T00:00:00.000Z..2026-09-21T00:00:00.000Z');
  expect(screen.getByLabelText('Query').getAttribute('value')).toBe(query);
  expect(mocks.page).toHaveBeenCalledExactlyOnceWith('lateral-restored', 0);
});

it('runs grouped stats without a histogram request or timeline', async () => {
  mocks.interactive.mockResolvedValue({
    results: [{ 'dst_endpoint.ip': '192.0.2.1', 'actor.process.name': 'SpeechModelDownload.exe', count: 7 }],
    total_count: 1, total_count_exact: true, fields: [], execution_time_ms: 50, display_type: 'table',
  });
  mount('metadata.log_source="windows_sysmon" category_name="Network Activity" actor.process.name="SpeechModelDownload.exe" | stats count by dst_endpoint.ip, actor.process.name | sort -count');
  fireEvent.click(screen.getByText('Run test search'));
  await waitFor(() => expect(screen.getByTestId('rows').textContent).toContain('SpeechModelDownload.exe'));
  expect(mocks.interactive).toHaveBeenCalledOnce();
  expect(mocks.interactive.mock.calls[0][0]).toMatchObject({ skip_histogram: true });
  expect(mocks.histogram).not.toHaveBeenCalled();
  expect(screen.queryByTestId('timeline')).toBeNull();
  expect(screen.getByTestId('hits').textContent).toBe('1');
});

it('keeps the event timeline when stats appears only in a query comment', async () => {
  mocks.interactive.mockResolvedValue({ results: [{ 'actor.user.name': 'jsmith' }], total_count: 1, fields: [], execution_time_ms: 50, display_type: 'events' });
  mount('actor.user.name="jsmith" /* | stats count */');
  fireEvent.click(screen.getByText('Run test search'));
  await waitFor(() => expect(screen.getByTestId('rows').textContent).toContain('jsmith'));
  expect(mocks.histogram).toHaveBeenCalledOnce();
  expect(screen.queryByTestId('timeline')).not.toBeNull();
});

// NAN-3263 — the live count is the rolling window's, not a client tally.
it('re-anchors the timeline count on the rolling window and rolls the range label and URL with it', async () => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  try {
    await mountTailed(paged(5));
    // The rolling window's server read: 12 five-minute buckets ending now.
    const bucket = 5 * 60_000;
    const lastStart = Math.floor(Date.now() / bucket) * bucket;
    const rolling = Array.from({ length: 13 }, (_, i) => ({
      time: new Date(lastStart - (12 - i) * bucket).toISOString(),
      count: 100 + i,
    }));
    const rollingTotal = rolling.reduce((n, b) => n + b.count, 0);
    mocks.histogram.mockResolvedValue({ histogram: rolling, total_count: rollingTotal });
    const histogramCalls = mocks.histogram.mock.calls.length;
    const urlUpdates = locations.length;
    expect(screen.getByTestId('time-range-label').textContent).toBe('');

    fireEvent.click(screen.getByText('tail -f'));
    await settleTicks(1, () => []);

    // One aggregate for the true window [now - 1h, now], not the 14:20–15:20
    // range the search started on.
    expect(mocks.histogram.mock.calls.length).toBe(histogramCalls + 1);
    const asked = mocks.histogram.mock.calls[histogramCalls][0] as { time_range: { start: string; end: string } };
    const askedEnd = Date.parse(asked.time_range.end);
    expect(askedEnd - Date.parse(asked.time_range.start)).toBe(60 * 60_000);
    expect(Math.abs(Date.now() - askedEnd)).toBeLessThan(60_000);

    // The timeline count is the server's count of that window.
    await waitFor(() => {
      const buckets = JSON.parse(screen.getByTestId('timeline').textContent!) as Array<{ events: number }>;
      expect(buckets.reduce((n, b) => n + b.events, 0)).toBe(rollingTotal);
    });

    // The label says the window is rolling, and the URL carries the anchored
    // window (replaced in place: `locations` sees the new URL once).
    expect(screen.getByTestId('time-range-label').textContent).toBe('Last 1h · live');
    const latest = new URLSearchParams(locations[locations.length - 1].split('?')[1]);
    expect(latest.get('start')).toBe(asked.time_range.start);
    expect(latest.get('end')).toBe(asked.time_range.end);
    expect(latest.get('q')).toBeTruthy();
    expect(locations.length).toBe(urlUpdates + 1);

    // No second aggregate until the re-anchor interval (1 min for 1h) passes.
    await settleTicks(2, () => []);
    expect(mocks.histogram.mock.calls.length).toBe(histogramCalls + 1);
    await settleTicks(2, () => []);
    expect(mocks.histogram.mock.calls.length).toBe(histogramCalls + 2);

    // Stopping the tail puts the picker's own range back.
    fireEvent.click(screen.getByText('tail -f'));
    await waitFor(() => expect(screen.getByTestId('time-range-label').textContent).toBe(''));
  } finally {
    vi.useRealTimers();
  }
});

// NAN-3267 — one live sample read "0 events" between 80,582 and 82,259.
it('holds the live count through an in-flight, zero-filled or empty re-anchor and a follow reconnect', async () => {
  const controllers: AbortController[] = [];
  const handlers: import('@/lib/api/types').SearchStreamCallbacks[] = [];
  mocks.stream.mockImplementation((_request, callbacks) => {
    const controller = new AbortController();
    controllers.push(controller);
    handlers.push(callbacks);
    queueMicrotask(() => callbacks.onStarted?.({ job_id: 'j', query_id: 'q', is_streaming: true }));
    return controller;
  });
  const timelineSum = () => (JSON.parse(screen.getByTestId('timeline').textContent!) as Array<{ events: number }>)
    .reduce((n, b) => n + b.events, 0);
  // One tail interval; the open follow stays alive on heartbeats.
  const step = async (ms = 15_000) => {
    await act(async () => { await vi.advanceTimersByTimeAsync(ms); });
    act(() => handlers[handlers.length - 1].onHeartbeat?.({ delivered: 0 }));
  };
  vi.useFakeTimers({ shouldAdvanceTime: true });
  try {
    await mountTailed(paged(5));
    mocks.legacy.mockResolvedValue({ results: [], total_count: 0, fields: [], execution_time_ms: 1 });
    // The rolling window's server read. The oldest bucket is empty, so the
    // chart sliding with the clock cannot move the sum during the test.
    const bucket = 5 * 60_000;
    const lastStart = Math.floor(Date.now() / bucket) * bucket;
    const times = Array.from({ length: 13 }, (_, i) => new Date(lastStart - (12 - i) * bucket).toISOString());
    const rolling = times.map((time, i) => ({ time, count: i === 0 ? 0 : 6_000 + i }));
    const rollingTotal = rolling.reduce((n, b) => n + b.count, 0);
    mocks.histogram.mockResolvedValueOnce({ histogram: rolling, total_count: rollingTotal });
    const calls = mocks.histogram.mock.calls.length;

    fireEvent.click(screen.getByText('tail -f'));
    await step();
    await waitFor(() => expect(timelineSum()).toBe(rollingTotal));
    expect(mocks.histogram.mock.calls.length).toBe(calls + 1);

    // The next re-anchor goes out and hangs: the count holds while it is in flight.
    let resolveInFlight!: (value: unknown) => void;
    mocks.histogram.mockImplementationOnce(() => new Promise(resolve => { resolveInFlight = resolve; }));
    for (let i = 0; i < 5 && mocks.histogram.mock.calls.length < calls + 2; i++) await step();
    expect(mocks.histogram.mock.calls.length).toBe(calls + 2);
    expect(timelineSum()).toBe(rollingTotal);

    // The follow drops and reconnects while that read is still pending.
    act(() => handlers[0].onError?.({ code: 'RESOURCE_EXHAUSTED', message: 'Interactive query exhausted its memory budget' }));
    await waitFor(() => expect(mocks.legacy).toHaveBeenCalled());
    expect(timelineSum()).toBe(rollingTotal);
    for (let i = 0; i < 3 && mocks.stream.mock.calls.length < 2; i++) await step(10_000);
    expect(mocks.stream).toHaveBeenCalledTimes(2);
    expect(controllers[0].signal.aborted).toBe(true);
    expect(timelineSum()).toBe(rollingTotal);

    // It resolves zero-filled over buckets that already hold events: not data.
    await act(async () => {
      resolveInFlight({ histogram: times.map(time => ({ time, count: 0 })), total_count: 0 });
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(timelineSum()).toBe(rollingTotal);

    // An empty read (a failed companion answers `histogram: []`) is not data either.
    mocks.histogram.mockResolvedValueOnce({ histogram: [] });
    for (let i = 0; i < 6 && mocks.histogram.mock.calls.length < calls + 3; i++) await step();
    expect(mocks.histogram.mock.calls.length).toBe(calls + 3);
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });
    expect(timelineSum()).toBe(rollingTotal);

    // A read with real data still replaces the timeline.
    const next = times.map((time, i) => ({ time, count: i === 0 ? 0 : 7_000 }));
    mocks.histogram.mockResolvedValueOnce({ histogram: next, total_count: 12 * 7_000 });
    for (let i = 0; i < 6 && mocks.histogram.mock.calls.length < calls + 4; i++) await step();
    await waitFor(() => expect(timelineSum()).toBe(12 * 7_000));
  } finally {
    vi.useRealTimers();
  }
});

// NAN-3273 — while tailing, the EVENT STREAM read "0 events" and drew an empty
// chart for a moment on every re-run of the same search over a moved window.
it('holds the timeline and its count across a window roll until the new read lands; an empty read still reads 0', async () => {
  const timelineSum = () => (JSON.parse(screen.getByTestId('timeline').textContent!) as Array<{ events: number }>)
    .reduce((n, b) => n + b.events, 0);
  const rows = { results: [{ 'metadata.uid': 'a' }], total_count: 1, fields: [], execution_time_ms: 1 };
  const first = [
    { time: '2026-09-21T14:20:00Z', count: 120_000 },
    { time: '2026-09-21T14:50:00Z', count: 80_000 },
  ];
  mocks.interactive.mockResolvedValue(rows);
  mocks.histogram.mockResolvedValueOnce({ histogram: first, total_count: 200_000 });
  mount('metadata.log_source="apache_access"');
  fireEvent.click(screen.getByText('Run test search'));
  await waitFor(() => expect(timelineSum()).toBe(200_000));

  // The window rolls (same search, new range): its read goes out and hangs.
  let land!: (value: unknown) => void;
  mocks.histogram.mockImplementationOnce(() => new Promise(resolve => { land = resolve; }));
  const histogramCalls = mocks.histogram.mock.calls.length;
  const sums: number[] = [];
  const unsub = setInterval(() => sums.push(timelineSum()), 0);
  fireEvent.click(screen.getByText('Pick last 24 hours'));
  await waitFor(() => expect(mocks.histogram.mock.calls.length).toBe(histogramCalls + 1));
  // The rows land first; the timeline read is still in flight.
  await waitFor(() => expect(screen.getByTestId('search-state').getAttribute('data-searching')).toBe('false'));
  expect(timelineSum()).toBe(200_000);
  clearInterval(unsub);
  expect(sums.every(n => n === 200_000)).toBe(true);

  // The read lands genuinely empty: that is the window's answer, so 0.
  await act(async () => { land({ histogram: [], total_count: 0 }); });
  await waitFor(() => expect(timelineSum()).toBe(0));
  // And the next roll holds that 0, never the older chart.
  mocks.histogram.mockImplementationOnce(() => new Promise(resolve => { land = resolve; }));
  fireEvent.click(screen.getByText('Pick last 24 hours'));
  fireEvent.click(screen.getByText('Run test search'));
  await waitFor(() => expect(mocks.histogram.mock.calls.length).toBe(histogramCalls + 2));
  await waitFor(() => expect(screen.getByTestId('search-state').getAttribute('data-searching')).toBe('false'));
  expect(timelineSum()).toBe(0);
  await act(async () => { land({ histogram: [], total_count: 0 }); });

  // A different search never shows the previous search's buckets.
  mocks.histogram.mockResolvedValueOnce({ histogram: first, total_count: 200_000 });
  fireEvent.click(screen.getByText('Pick absolute window'));
  await waitFor(() => expect(timelineSum()).toBe(200_000));
  mocks.histogram.mockImplementationOnce(() => new Promise(() => {}));
  fireEvent.change(screen.getByLabelText('Query'), { target: { value: 'metadata.log_source="nginx"' } });
  fireEvent.click(screen.getByText('Run test search'));
  await waitFor(() => expect(timelineSum()).toBe(0));
});

// NAN-3299: one run is one set of calls. Each request holds a per-user
// admission permit on the server; a duplicate run exhausted the budget.

it('a page load over a relative range runs once: one search, one timeline, one field-stats', async () => {
  mocks.interactive.mockResolvedValue({ results: [{ 'actor.user.name': 'jsmith' }], total_count: 1, fields: [], execution_time_ms: 1, display_type: 'table' });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  client.setQueryData(['schema-fields'], mocks.schema);
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/search?q=actor.user.name%3D%22jsmith%22&time=Last+hour']}><LocationProbe /><Search /></MemoryRouter></QueryClientProvider>);
  await waitFor(() => expect(screen.getByTestId('rows').textContent).toContain('jsmith'));
  await waitFor(() => expect(mocks.fields).toHaveBeenCalled());
  // Past the URL-sync effect's re-run delay: nothing else fires.
  await act(async () => { await new Promise(resolve => setTimeout(resolve, 400)); });

  expect(mocks.interactive).toHaveBeenCalledOnce();
  expect(mocks.histogram).toHaveBeenCalledOnce();
  expect(mocks.fields).toHaveBeenCalledOnce();
  const ran = mocks.interactive.mock.calls[0][0].time_range;
  expect(Date.parse(ran.end) - Date.parse(ran.start)).toBe(3600_000);
  // Timeline and field stats read the run's own bounds.
  expect(mocks.histogram.mock.calls[0][0].time_range).toEqual(ran);
  expect(mocks.fields.mock.calls[0][0]).toMatchObject({ start: ran.start, end: ran.end });
  // NAN-3884: the URL keeps the relative pick (a reload or shared link
  // re-resolves it), and so does the picker. The run's resolved bounds show
  // in the meta row instead.
  const url = new URLSearchParams(locations.at(-1)!.split('?')[1]);
  expect(url.get('time')).toBe('Last hour');
  expect(url.get('start')).toBeNull();
  expect(url.get('end')).toBeNull();
  expect(screen.getByTestId('time-range').textContent).toBe('preset:Last hour');
  expect(screen.getByTestId('run-time-window').textContent).toMatch(/^1h · .+ → .+$/);
  // The field panel is scoped to that run (one ext-field key per run).
  expect(mocks.panel.mock.lastCall![0]).toMatchObject({ query: 'actor.user.name="jsmith"', timeRange: ran });
});

it('one click of run is one set of calls, and the field panel ignores unrun editor text', async () => {
  mocks.interactive.mockResolvedValue({ results: [{ 'actor.user.name': 'jsmith' }], total_count: 1, fields: [], execution_time_ms: 1, display_type: 'table' });
  mount('actor.user.name="jsmith"', '/search?time=Last+hour');
  fireEvent.click(screen.getByText('Run test search'));
  await waitFor(() => expect(mocks.fields).toHaveBeenCalled());
  await act(async () => { await new Promise(resolve => setTimeout(resolve, 400)); });
  expect(mocks.interactive).toHaveBeenCalledOnce();
  expect(mocks.histogram).toHaveBeenCalledOnce();
  expect(mocks.fields).toHaveBeenCalledOnce();

  const ran = mocks.interactive.mock.calls[0][0].time_range;
  fireEvent.change(screen.getByLabelText('Query'), { target: { value: 'actor.user.name="jsm' } });
  expect(mocks.panel.mock.lastCall![0]).toMatchObject({ query: 'actor.user.name="jsmith"', timeRange: ran });
});

it('a page flip keeps the run window of a relative range', async () => {
  const rows = Array.from({ length: 50 }, (_, uid) => ({ uid }));
  mocks.interactive.mockResolvedValueOnce({ results: rows, total_count: 100, fields: [], execution_time_ms: 1, display_type: 'table' })
    .mockResolvedValue({ results: [{ uid: 50 }], total_count: 100, fields: [], execution_time_ms: 1, display_type: 'table' });
  mount('actor.user.name="jsmith"', '/search?time=Last+hour');
  fireEvent.click(screen.getByText('Run test search'));
  await waitFor(() => expect(JSON.parse(screen.getByTestId('rows').textContent!)).toHaveLength(50));
  await act(async () => { await new Promise(resolve => setTimeout(resolve, 20)); });
  fireEvent.click(screen.getByText('Load test page'));
  await waitFor(() => expect(mocks.interactive).toHaveBeenCalledTimes(2));
  expect(mocks.interactive.mock.calls[1][0].time_range).toEqual(mocks.interactive.mock.calls[0][0].time_range);
});

it('a newer run aborts the superseded run\'s timeline and field-stats requests', async () => {
  mocks.interactive.mockResolvedValue({ results: [{ 'actor.user.name': 'jsmith' }], total_count: 1, fields: [], execution_time_ms: 1, display_type: 'table' });
  mocks.histogram.mockImplementation(() => new Promise(() => {}));
  mocks.fields.mockImplementation(() => new Promise(() => {}));
  mount();
  fireEvent.click(screen.getByText('Run test search'));
  await waitFor(() => expect(mocks.fields).toHaveBeenCalledOnce());
  const firstHistogram: AbortSignal = mocks.histogram.mock.calls[0][1];
  const firstStats: AbortSignal = mocks.fields.mock.calls[0][0].signal;
  expect(firstStats).toBeInstanceOf(AbortSignal);
  expect(firstStats.aborted).toBe(false);

  fireEvent.click(screen.getByText('Run test search'));
  await waitFor(() => expect(mocks.fields).toHaveBeenCalledTimes(2));
  expect(firstHistogram.aborted).toBe(true);
  expect(firstStats.aborted).toBe(true);
  expect(mocks.fields.mock.calls[1][0].signal.aborted).toBe(false);

  // Leaving the page aborts the live run's requests too.
  const secondStats: AbortSignal = mocks.fields.mock.calls[1][0].signal;
  cleanup();
  expect(secondStats.aborted).toBe(true);
});
