// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
//
// NAN-4589 — Search Analyze runs in the pivt panel. Through the real pivt shell
// (PivtShellOverlay → PivtPanel → PivtPanelBody → PivtInput → command router)
// next to the real Search page:
//   - the Analyze button and `@summarize [focus]` start a panel run carrying
//     the page's query, window and rows; the results stay on screen
//   - the narrative, findings and pivot searches render as a pivt card; a pivot
//     opens Search with that query in the same window and runs it
//   - the focus is carried (brief, context row, ordering), not dropped
//   - no results / off Search / a failed job are reported in pivt
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { PageContextProvider } from '@/contexts/PageContext';
import { PivtShellOverlay } from '@/enterprise/components/pivt/PivtShellOverlay';
import { resetPivtDraftStore } from '@/enterprise/components/pivt/drafts/draft-store';
import { NO_SEARCH_TO_ANALYZE } from '@/enterprise/components/pivt/drafts/search-analysis';
import { usePivtState } from '@/enterprise/hooks/use-pivt-state';
import type { SearchSummary } from '@/lib/api';

const mocks = vi.hoisted(() => ({
  interactive: vi.fn(),
  histogram: vi.fn(),
  stream: vi.fn(),
  fields: vi.fn(),
  history: vi.fn(),
  noop: vi.fn(),
  mutation: vi.fn().mockResolvedValue({}),
  melodSummarize: vi.fn(),
  job: {
    outcome: { kind: 'ok' } as { kind: 'ok'; value?: unknown } | { kind: 'fail'; message: string },
    release: null as null | (() => void),
    hold: false,
  },
  schema: { schema: 'ocsf', fields: [] as Array<{ name: string }> },
}));

vi.mock('@/lib/api', () => ({
  ApiClientError: class extends Error {},
  api: {
    searchInteractive: mocks.interactive,
    searchHistogram: mocks.histogram,
    searchStreamSSE: mocks.stream,
    searchAsync: vi.fn(),
    getSearchJob: vi.fn(),
    getSearchJobResultPage: vi.fn(),
    cancelSearch: vi.fn().mockResolvedValue({}),
    cancelSearchJob: vi.fn().mockResolvedValue({}),
    getExtFieldNames: async () => [],
    getSchemaFields: async () => mocks.schema,
    listSearchJobs: async () => [],
    melodSummarize: mocks.melodSummarize,
  },
}));
vi.mock('@/hooks/use-api', async (importOriginal) => {
  const original = await importOriginal<typeof import('@/hooks/use-api')>();
  const hooks = Object.fromEntries(
    Object.keys(original)
      .filter((key) => key.startsWith('use'))
      .map((key) => [key, () => ({ mutate: mocks.mutation, data: undefined, loading: false, refetch: mocks.noop })]),
  );
  return {
    ...original,
    ...hooks,
    useSearch: () => ({ mutate: vi.fn() }),
    useFieldStats: () => ({ mutate: mocks.fields }),
    useMelodStatus: () => ({ data: { connected: true } }),
  };
});
vi.mock('@/hooks/use-capabilities', async (importOriginal) => ({
  ...(await importOriginal<object>()),
  useCapabilities: () => ({
    edition: 'enterprise',
    capabilities: { search: true, melod: true },
    tenantPlan: { identity: { permissions: [] }, components: {} },
  }),
}));
vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({
    user: { id: 'me', name: 'Dan Lussier' },
    hasPermission: () => true,
    hasAnyPermission: () => true,
    isAuthenticated: true,
    isDemoUser: false,
  }),
}));
vi.mock('@/contexts/UserPreferencesContext', () => ({
  useUserPreferences: () => ({ defaultTimeRange: '1h', queryMode: 'piped' }),
}));
vi.mock('@/hooks/useSearchHistory', () => ({
  useSearchHistory: () => ({ searchHistory: [], addToSearchHistory: mocks.history, refreshHistory: mocks.noop }),
}));
vi.mock('@/hooks/use-mobile', () => ({ useIsMobile: () => false }));
vi.mock('@/components/search/retro/useRetro', () => ({ primeDurableRetroResult: () => {} }));
vi.mock('@/components/reports/ScheduleReportDialog', () => ({ ScheduleReportDialog: () => null }));
vi.mock('@/components/dashboard', () => ({ AddToDashboardDialog: () => null }));
vi.mock('@/components/DemoHints', () => ({ SearchDemoHint: () => null }));
// Cases-coupled; the analysis never touches it.
vi.mock('@/enterprise/components/pivt/PivtCloseDialog', () => ({ PivtCloseDialog: () => null }));
vi.mock('@/components/threat-intel/use-threat-intel', () => ({ useEnrichEnabled: () => false }));
// The poller has its own tests; here the job settles once the start request
// was sent (optionally held open to observe the in-flight panel state).
vi.mock('@/enterprise/hooks/use-melod-job', () => ({
  useMelodJob: () => ({ loading: false, start: vi.fn(), cancel: vi.fn() }),
  pollMelodJob: async (fn: () => Promise<unknown>, opts?: { onProgress?: (m?: string) => void }) => {
    await fn();
    opts?.onProgress?.('Scoring rare values');
    if (mocks.job.hold) await new Promise<void>((r) => (mocks.job.release = r));
    const outcome = mocks.job.outcome;
    if (outcome.kind === 'fail') throw new Error(outcome.message);
    return outcome.value;
  },
}));
(globalThis as unknown as { ResizeObserver: unknown }).ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
};

import { Search } from './Search';

const ROWS = [
  { message: 'Failed password for root from 203.0.113.50', src_ip: '203.0.113.50', user: 'root' },
  { message: 'Failed password for admin from 203.0.113.50', src_ip: '203.0.113.50', user: 'admin' },
  { message: 'Accepted publickey for deploy from 10.0.0.5', src_ip: '10.0.0.5', user: 'deploy' },
];

const SUMMARY: SearchSummary = {
  narrative: 'Brute-force pattern: 2 of 3 events are failed root/admin logins from one external IP.',
  key_findings: [
    { category: 'volume', title: 'Steady background noise', description: 'Deploy key logins are routine.', importance: 'low', related_fields: ['user'] },
    { category: 'auth', title: 'External password spraying', description: 'Failed logins for privileged users from 203.0.113.50.', importance: 'high', related_fields: ['src_ip', 'user'] },
  ],
  suspicious_items: [
    { field: 'src_ip', anomaly_type: 'dominance', title: 'One source dominates failures', description: '', value: '203.0.113.50', percentage: 66.7, severity: 'high' },
  ],
  suggested_queries: [
    { description: 'Every event from the spraying IP', query: 'src_ip="203.0.113.50"', rationale: '', priority: 'high' },
    { description: 'Successful logins after the failures', query: 'Accepted | stats count by user, src_ip', rationale: '', priority: 'medium' },
  ],
  risk_assessment: { level: 'high', explanation: 'Privileged accounts are being guessed from the internet.', indicators: [] },
};

function Where() {
  const loc = useLocation();
  return <div data-testid="where">{loc.pathname + loc.hash}</div>;
}

function Shell() {
  const pivt = usePivtState();
  return (
    <PivtShellOverlay state={pivt}>
      <Where />
      <Routes>
        <Route path="/" element={<div>home</div>} />
        <Route path="/search" element={<Search />} />
      </Routes>
    </PivtShellOverlay>
  );
}

function renderAt(path: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  client.setQueryData(['schema-fields'], mocks.schema);
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <PageContextProvider>
          <Shell />
        </PageContextProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function send(text: string) {
  const input = screen.getByLabelText('Message pivt') as HTMLTextAreaElement;
  fireEvent.change(input, { target: { value: text } });
  fireEvent.keyDown(input, { key: 'Enter' });
}

const SEARCH_URL = '/search#q=Failed+OR+Accepted&time=Last+24+hours';

async function searchWithResults() {
  renderAt(SEARCH_URL);
  await waitFor(() => expect(mocks.interactive).toHaveBeenCalled());
  return screen.findByRole('button', { name: /Analyze/ });
}

const resultsVisible = () => screen.getAllByText(/Failed password for root/).length > 0;

beforeEach(() => {
  localStorage.clear();
  sessionStorage.clear();
  resetPivtDraftStore();
  vi.clearAllMocks();
  mocks.job.outcome = { kind: 'ok', value: SUMMARY };
  mocks.job.hold = false;
  mocks.job.release = null;
  mocks.melodSummarize.mockResolvedValue({ job_id: 'j1', status: 'pending' });
  mocks.fields.mockResolvedValue({ fields: [] });
  mocks.histogram.mockResolvedValue({ histogram: [{ time: '2026-10-26T10:00:00Z', count: 3 }] });
  mocks.stream.mockImplementation((_request: unknown, callbacks: { onError?: (e: unknown) => void }) => {
    queueMicrotask(() => callbacks.onError?.({ code: 'VALIDATION_ERROR', message: 'gen1 tenant' }));
    return new AbortController();
  });
  mocks.interactive.mockImplementation(async () => ({
    results: ROWS,
    total_count: 1250,
    fields: [],
    execution_time_ms: 4,
    display_type: 'table',
  }));
});
afterEach(cleanup);

describe('Search Analyze runs in the pivt panel', () => {
  test('Analyze sends the page context, shows progress, then the analysis card; results stay', async () => {
    mocks.job.hold = true;
    fireEvent.click(await searchWithResults());

    await waitFor(() => expect(mocks.melodSummarize).toHaveBeenCalledTimes(1));
    const request = mocks.melodSummarize.mock.calls[0][0];
    expect(request.query).toBe('Failed OR Accepted');
    expect(request.query_mode).toBe('piped');
    expect(request.total_count).toBe(1250);
    // No focus from the button: the field is omitted, not sent blank.
    expect('focus' in request).toBe(false);
    expect(request.results).toHaveLength(ROWS.length);
    expect(request.results[0]).toMatchObject({ user: 'root' });
    expect(request.time_range.start).toEqual(expect.any(String));
    expect(Date.parse(request.time_range.end) - Date.parse(request.time_range.start)).toBeGreaterThan(23 * 3600_000);

    // pivt opened and shows the run in progress next to the results.
    expect(localStorage.getItem('nano-pivt-open')).toBe('1');
    const run = await screen.findByTestId('pivt-draft-run');
    expect(run.getAttribute('data-status')).toBe('running');
    expect(within(run).getByText('Analyze these results')).toBeTruthy();
    expect(within(run).getByText('Analyzing these search results…')).toBeTruthy();
    expect(within(run).getByText('Failed OR Accepted')).toBeTruthy();
    expect(within(run).getByText('3 of 1,250')).toBeTruthy();
    expect(await within(run).findAllByText('Scoring rare values')).not.toHaveLength(0);
    expect(resultsVisible()).toBe(true);

    act(() => mocks.job.release?.());
    await waitFor(() => expect(run.getAttribute('data-status')).toBe('done'));
    const card = within(run);
    expect(card.getByText('High')).toBeTruthy();
    expect(card.getByText(/Brute-force pattern/)).toBeTruthy();
    expect(card.getByText(/Privileged accounts are being guessed/)).toBeTruthy();
    expect(card.getByText(/High · External password spraying/)).toBeTruthy();
    expect(card.getByText(/One source dominates failures: src_ip=203.0.113.50 \(67% of events\)/)).toBeTruthy();

    // Pivots: suggested searches, then the suspicious-value drill-down (deduped).
    const pivots = card.getAllByTestId('pivt-pivot-query');
    expect(pivots.map((p) => p.querySelector('code')?.textContent)).toEqual([
      'src_ip="203.0.113.50"',
      'Accepted | stats count by user, src_ip',
    ]);
    // Same window as the analyzed run.
    expect(pivots[0].getAttribute('href')).toBe(`/search#q=${encodeURIComponent('src_ip="203.0.113.50"').replace(/%20/g, '+')}&time=Last+24+hours`);

    // The results never left the page and no modal opened.
    expect(resultsVisible()).toBe(true);
    expect(screen.queryByRole('dialog')).toBeNull();
  }, 20_000);

  test('a pivot writes the query bar and runs it in the same window', async () => {
    fireEvent.click(await searchWithResults());
    const run = await screen.findByTestId('pivt-draft-run');
    await waitFor(() => expect(run.getAttribute('data-status')).toBe('done'));
    const before = mocks.interactive.mock.calls.length;

    fireEvent.click(within(run).getAllByTestId('pivt-pivot-query')[1]);
    await waitFor(() => expect(mocks.interactive.mock.calls.length).toBeGreaterThan(before));
    const last = mocks.interactive.mock.calls.at(-1)![0];
    expect(last.query).toBe('Accepted | stats count by user, src_ip');
    expect(screen.getByTestId('where').textContent).toContain('time=Last+24+hours');
    // pivt keeps the card while the page re-runs.
    expect(screen.getByTestId('pivt-draft-run').getAttribute('data-status')).toBe('done');
  }, 20_000);

  test('@summarize carries the focus: brief, context row and ordering', async () => {
    await searchWithResults();
    send('@summarize password spraying');
    await waitFor(() => expect(mocks.melodSummarize).toHaveBeenCalledTimes(1));
    // NAN-4594: the model gets the focus too.
    expect(mocks.melodSummarize.mock.calls[0][0].focus).toBe('password spraying');
    const run = await screen.findByTestId('pivt-draft-run');
    await waitFor(() => expect(run.getAttribute('data-status')).toBe('done'));
    const card = within(run);
    expect(card.getByText('Analyze these results, focusing on password spraying')).toBeTruthy();
    expect(card.getByText('Focus')).toBeTruthy();
    expect(card.getByText('password spraying')).toBeTruthy();
    // The finding that mentions the focus moves ahead of the model's first one.
    const items = card.getAllByText(/^(High|Low) · /).map((n) => n.textContent);
    expect(items[0]).toMatch(/External password spraying/);
    expect(items[1]).toMatch(/Steady background noise/);
  }, 20_000);

  test('the Search here-card suggestion "Summarize these results" analyzes too', async () => {
    localStorage.setItem('nano-pivt-open', '1');
    await searchWithResults();
    fireEvent.click(await screen.findByRole('button', { name: /Summarize these results/ }));
    await waitFor(() => expect(mocks.melodSummarize).toHaveBeenCalledTimes(1));
    expect(await screen.findByTestId('pivt-draft-run')).toBeTruthy();
  }, 20_000);

  test('a failed analysis is reported in pivt and the results stay', async () => {
    mocks.job.outcome = { kind: 'fail', message: 'AI provider not configured' };
    fireEvent.click(await searchWithResults());
    const run = await screen.findByTestId('pivt-draft-run');
    await waitFor(() => expect(run.getAttribute('data-status')).toBe('failed'));
    expect(within(run).getByText('pivt could not analyze these results.')).toBeTruthy();
    expect(within(run).getByText('AI provider not configured')).toBeTruthy();
    expect(resultsVisible()).toBe(true);
  }, 20_000);

  test('@summarize off Search says there is nothing to analyze and calls nothing', async () => {
    renderAt('/');
    send('@summarize failed logins');
    const run = await screen.findByTestId('pivt-draft-run');
    await waitFor(() => expect(run.getAttribute('data-status')).toBe('failed'));
    expect(within(run).getByText(NO_SEARCH_TO_ANALYZE)).toBeTruthy();
    expect(mocks.melodSummarize).not.toHaveBeenCalled();
    expect(screen.getByTestId('where').textContent).toBe('/');
  });
});
