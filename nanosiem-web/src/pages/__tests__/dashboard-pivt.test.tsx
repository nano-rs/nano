// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
//
// NAN-4600 — pivt generates dashboards inline in its panel (no builder sheet).
// Through the real pivt shell (PivtShellOverlay → PivtPanel → PivtInput →
// command router) next to the real Dashboards page:
//   - "create a dashboard of …" / `@dashboard <brief>` generate in the panel
//   - clarifying questions are answer cards; answers go back with the session
//   - the preview is a card; Save creates the dashboard and opens it,
//     Discard saves nothing
//   - the page's "Generate with pivt" opens the panel; blank create is the
//     core dialog
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import type { Capabilities } from '@/hooks/use-capabilities';
import type { GenerateDashboardResponse, GeneratedDashboard } from '@/lib/api/types';

const mock = vi.hoisted(() => ({
  perms: new Set(['dashboards:view', 'dashboards:create', 'melod:dashboard', 'search:execute']),
  jobResults: [] as unknown[],
  melodGenerateDashboard: vi.fn(),
  createDashboard: vi.fn(),
  listDashboards: vi.fn(),
}));

function caps(): Capabilities {
  return {
    search: true, cases: false, notebooks: false, risk: false, melod: true, queryCorrection: false,
    customEnrichment: false, agentEnrichment: false, aiTuning: false, playbooks: false, incidents: false,
    siemHealth: true, sso: true, observabilityConvergence: false, iocLists: true, soar: false,
  };
}

// Any API surface the page touches resolves empty; the calls under test are explicit.
function autoApi(overrides: Record<string, unknown>): unknown {
  const make = (path: string): unknown =>
    new Proxy(() => Promise.resolve(null), {
      get(_t, prop) {
        if (prop === 'then') return undefined;
        const key = path ? `${path}.${String(prop)}` : String(prop);
        if (key in overrides) return overrides[key];
        return make(key);
      },
      apply() {
        return Promise.resolve(null);
      },
    });
  return make('');
}

vi.mock('@/lib/api', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  return {
    ...actual,
    api: autoApi({ melodGenerateDashboard: mock.melodGenerateDashboard, createDashboard: mock.createDashboard, listDashboards: mock.listDashboards }),
  };
});
vi.mock('@/hooks/use-api', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  const idle = () => ({ data: undefined, loading: false, isLoading: false, error: null, refetch: vi.fn(), mutate: vi.fn() });
  const stubs: Record<string, unknown> = {};
  for (const key of Object.keys(actual)) {
    stubs[key] = typeof actual[key] === 'function' && key.startsWith('use') ? idle : actual[key];
  }
  return {
    ...stubs,
    useMelodStatus: () => ({ data: { connected: true } }),
    useDashboards: () => ({ data: [], loading: false, refetch: vi.fn() }),
  };
});
vi.mock('@/hooks/useRecentlyViewedDashboards', () => ({
  useRecentlyViewedDashboards: () => ({ recentDashboardIds: [], removeRecentDashboard: vi.fn() }),
}));
vi.mock('@/hooks/use-capabilities', async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  useCapabilities: () => ({ edition: 'enterprise', version: 'test', capabilities: caps() }),
}));
vi.mock('@/enterprise/components/pivt/PivtCloseDialog', () => ({ PivtCloseDialog: () => null }));
vi.mock('@/components/threat-intel/use-threat-intel', () => ({ useEnrichEnabled: () => false }));
vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({
    hasPermission: (p: string) => mock.perms.has(p),
    hasAnyPermission: (ps: string[]) => ps.some((p) => mock.perms.has(p)),
    isDemoUser: false,
    user: { id: 'me', name: 'Dan Lussier', deployment_mode: 'enterprise_shared' },
  }),
}));
vi.mock('@/enterprise/hooks/use-melod-job', () => ({
  pollMelodJob: async (fn: () => Promise<unknown>, opts?: { onProgress?: (m?: string) => void }) => {
    await fn();
    opts?.onProgress?.('Validating panel queries');
    const next = mock.jobResults.shift();
    if (next instanceof Error) throw next;
    return next;
  },
  useMelodJob: () => ({ start: vi.fn(), result: null, error: null, loading: false, progress: null, reset: vi.fn() }),
}));

import { BreadcrumbProvider } from '@/contexts/BreadcrumbContext';
import { PivtShellOverlay } from '@/enterprise/components/pivt/PivtShellOverlay';
import { resetPivtDraftStore } from '@/enterprise/components/pivt/drafts/draft-store';
import { resetRunActions } from '@/enterprise/components/pivt/drafts/interactive';
import { usePivtState } from '@/enterprise/hooks/use-pivt-state';
import { Dashboards } from '../Dashboards';

const BRIEF = 'create a dashboard of failed logins by country for the last 7 days';

const QUESTIONS: GenerateDashboardResponse = {
  session_id: 'sess-1',
  message: '',
  is_complete: false,
  clarifying_questions: [
    { id: 'window', question: 'Which time window?', question_type: 'single_choice', options: ['24h', '7d'], required: true },
    { id: 'sources', question: 'Which auth sources?', question_type: 'multi_choice', options: ['okta', 'vpn', 'ad'], required: true },
    { id: 'geo', question: 'Group by country or ASN?', question_type: 'free_text', default_answer: 'country', required: false },
  ],
};

const DASH: GeneratedDashboard = {
  name: 'Failed logins by country',
  description: 'Failed authentication over 7 days by source country.',
  explanation: 'Built from okta and vpn auth events.',
  panels: [
    { id: 'p1', title: 'Failed logins over time', query: 'auth_result=failure | timechart span=1h count', query_mode: 'piped', visualization_type: 'line', visualization_config: {} },
    { id: 'p2', title: 'Top countries', query: 'auth_result=failure | stats count by enriched_src_country', query_mode: 'piped', visualization_type: 'bar', visualization_config: {} },
    { id: 'p3', title: 'Failed logins', query: 'auth_result=failure | stats count', query_mode: 'piped', visualization_type: 'single_value', visualization_config: {} },
  ],
  layout: {
    columns: 12, row_height: 100,
    items: [
      { panel_id: 'p1', x: 0, y: 0, w: 8, h: 3 },
      { panel_id: 'p3', x: 8, y: 0, w: 4, h: 3 },
      { panel_id: 'p2', x: 0, y: 3, w: 12, h: 3 },
    ],
  },
  variables: [{ name: 'country', label: 'Country', variable_type: 'text' }],
  refresh_interval: 300,
  is_complete: true,
};
const DONE: GenerateDashboardResponse = { session_id: 'sess-1', message: '', is_complete: true, dashboard: DASH };

let where = '';
function Where() {
  const loc = useLocation();
  where = `${loc.pathname}${loc.search}`;
  return null;
}

function Shell() {
  const pivt = usePivtState();
  return (
    <PivtShellOverlay state={pivt}>
      <Where />
      <Routes>
        <Route path="/" element={<div>home</div>} />
        <Route path="/dashboards" element={<Dashboards />} />
        <Route path="/dashboards/:id" element={<div>dashboard view</div>} />
      </Routes>
    </PivtShellOverlay>
  );
}

function renderAt(path: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <BreadcrumbProvider>
          <Shell />
        </BreadcrumbProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const pivtInput = () => screen.getByLabelText('Message pivt') as HTMLTextAreaElement;
function send(text: string) {
  fireEvent.change(pivtInput(), { target: { value: text } });
  fireEvent.keyDown(pivtInput(), { key: 'Enter' });
}
const runs = () => screen.queryAllByTestId('pivt-draft-run');
async function settledRun(index: number, status = 'done') {
  await waitFor(() => expect(runs().length).toBeGreaterThan(index));
  const run = runs()[index];
  await waitFor(() => expect(run.getAttribute('data-status')).toBe(status));
  return run;
}
function card(run: HTMLElement, title: string) {
  const el = within(run).getAllByTestId('pivt-run-card').find((c) => within(c).queryByText(title));
  if (!el) throw new Error(`no card ${title}`);
  return el;
}

beforeEach(() => {
  localStorage.clear();
  localStorage.setItem('nano-pivt-open', '1');
  resetPivtDraftStore();
  resetRunActions();
  mock.perms = new Set(['dashboards:view', 'dashboards:create', 'melod:dashboard', 'search:execute']);
  mock.jobResults = [];
  mock.melodGenerateDashboard.mockReset().mockResolvedValue({ job_id: 'j1', status: 'running' });
  mock.createDashboard.mockReset().mockResolvedValue({ id: 'dash-42', name: DASH.name });
  mock.listDashboards.mockReset().mockResolvedValue([]);
  vi.stubGlobal('matchMedia', (query: string) => ({
    matches: false, media: query, onchange: null,
    addEventListener: () => {}, removeEventListener: () => {}, addListener: () => {}, removeListener: () => {},
    dispatchEvent: () => false,
  }));
  Element.prototype.scrollIntoView = () => {};
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} });
  vi.stubGlobal('fetch', vi.fn(async () => new Response('[]', { status: 200, headers: { 'Content-Type': 'application/json' } })));
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('pivt generates dashboards in its panel', () => {
  test('questions are answer cards; answers go back with the session; Save creates it and opens /dashboards/:id', async () => {
    mock.jobResults = [QUESTIONS, DONE];
    renderAt('/');
    send(BRIEF);
    await waitFor(() => expect(mock.melodGenerateDashboard).toHaveBeenCalledWith({ description: BRIEF, session_id: undefined, answers: undefined }));
    const asked = await settledRun(0);
    expect(within(asked).getByText(BRIEF)).toBeTruthy();
    expect(within(asked).getByText(/3 questions before pivt builds the dashboard/)).toBeTruthy();

    // Choice → buttons; multi-choice → typed list; optional → default.
    fireEvent.click(within(card(asked, 'Which time window?')).getByRole('button', { name: /7d/ }));
    await waitFor(() => expect(within(card(asked, 'Which time window?')).getByText('Answer: 7d')).toBeTruthy());
    const sources = card(asked, 'Which auth sources?');
    expect(within(sources).getByText(/Options: okta, vpn, ad/)).toBeTruthy();
    fireEvent.change(within(sources).getByLabelText('Which auth sources?'), { target: { value: 'okta, vpn' } });
    fireEvent.click(within(sources).getByRole('button', { name: 'Answer' }));
    await waitFor(() => expect(within(sources).getByText('Answer: okta, vpn')).toBeTruthy());
    expect(mock.melodGenerateDashboard).toHaveBeenCalledTimes(1);
    fireEvent.click(within(card(asked, 'Group by country or ASN?')).getByRole('button', { name: 'Use default' }));

    await waitFor(() => expect(mock.melodGenerateDashboard).toHaveBeenCalledTimes(2));
    expect(mock.melodGenerateDashboard).toHaveBeenLastCalledWith({
      description: BRIEF,
      session_id: 'sess-1',
      answers: { window: '7d', sources: ['okta', 'vpn'], geo: 'country' },
    });
    const preview = await settledRun(1);
    expect(within(preview).getByText('My answers: 7d · okta, vpn · country')).toBeTruthy();
    expect(card(asked, 'Group by country or ASN?').getAttribute('data-state')).toBe('answered');
    expect(within(preview).getByText(/3 panels. Save it to open it/)).toBeTruthy();
    const save = card(preview, 'Failed logins by country');
    expect(within(save).getByLabelText('Dashboard layout preview')).toBeTruthy();
    expect(within(save).getByText('Failed logins over time · line')).toBeTruthy();
    expect(within(save).getByText('Failed logins · stat')).toBeTruthy();
    expect(within(save).getByText('not saved')).toBeTruthy();
    expect(mock.createDashboard).not.toHaveBeenCalled();
    expect(where).toBe('/');

    fireEvent.click(within(save).getByRole('button', { name: /Save dashboard/ }));
    await waitFor(() => expect(where).toBe('/dashboards/dash-42'));
    const req = mock.createDashboard.mock.calls[0][0];
    expect(req.name).toBe('Failed logins by country');
    expect(req.visibility).toBe('private');
    expect(req.refresh_interval).toBe(300);
    expect(req.layout.items).toEqual([
      { i: 'p1', x: 0, y: 0, w: 8, h: 3 },
      { i: 'p3', x: 8, y: 0, w: 4, h: 3 },
      { i: 'p2', x: 0, y: 3, w: 12, h: 3 },
    ]);
    expect(req.panels.map((p: { queryMode: string; timeRangeMode: string }) => [p.queryMode, p.timeRangeMode])).toEqual([
      ['piped', 'dashboard'], ['piped', 'dashboard'], ['piped', 'dashboard'],
    ]);
    expect(within(save).getByText(/Saved as a private dashboard/)).toBeTruthy();
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  test('Discard saves nothing; a failed save stays retryable', async () => {
    mock.jobResults = [DONE, DONE];
    renderAt('/');
    send('@dashboard failed logins by country');
    const first = await settledRun(0);
    fireEvent.click(within(card(first, DASH.name)).getByRole('button', { name: 'Discard' }));
    await waitFor(() => expect(card(first, DASH.name).getAttribute('data-state')).toBe('rejected'));
    expect(mock.createDashboard).not.toHaveBeenCalled();

    mock.createDashboard.mockRejectedValueOnce(new Error('panel p2: unknown field enriched_src_country'));
    send('@dashboard failed logins by country');
    const second = await settledRun(1);
    fireEvent.click(within(card(second, DASH.name)).getByRole('button', { name: /Save dashboard/ }));
    await waitFor(() => expect(within(card(second, DASH.name)).getByText(/unknown field/)).toBeTruthy());
    expect(where).toBe('/');
    fireEvent.click(within(card(second, DASH.name)).getByRole('button', { name: /Save dashboard/ }));
    await waitFor(() => expect(where).toBe('/dashboards/dash-42'));
    expect(mock.createDashboard).toHaveBeenCalledTimes(2);
  });

  test('a typed multi-choice answer must name offered options (NAN-4607)', async () => {
    mock.jobResults = [
      { session_id: 's', message: '', is_complete: false, clarifying_questions: [QUESTIONS.clarifying_questions![1]] },
      DONE,
    ];
    renderAt('/');
    send('@dashboard failed logins');
    const run = await settledRun(0);
    const q = card(run, 'Which auth sources?');
    fireEvent.change(within(q).getByLabelText('Which auth sources?'), { target: { value: 'okta, syslog' } });
    fireEvent.click(within(q).getByRole('button', { name: 'Answer' }));
    await waitFor(() => expect(q.getAttribute('data-state')).toBe('failed'));
    expect(within(q).getByText('Not an option: syslog. Pick from: okta, vpn, ad.')).toBeTruthy();
    expect(mock.melodGenerateDashboard).toHaveBeenCalledTimes(1);

    // Any case is accepted and sent with the offered spelling, once.
    fireEvent.change(within(q).getByLabelText('Which auth sources?'), { target: { value: 'OKTA, vpn, okta' } });
    fireEvent.click(within(q).getByRole('button', { name: 'Answer' }));
    await waitFor(() => expect(within(q).getByText('Answer: okta, vpn')).toBeTruthy());
    await waitFor(() => expect(mock.melodGenerateDashboard).toHaveBeenCalledTimes(2));
    expect(mock.melodGenerateDashboard).toHaveBeenLastCalledWith({
      description: 'failed logins', session_id: 's', answers: { sources: ['okta', 'vpn'] },
    });
  });

  test('a failed follow-up round keeps the answers; Retry resends them in the same session (NAN-4607)', async () => {
    mock.jobResults = [
      { session_id: 's', message: '', is_complete: false, clarifying_questions: [QUESTIONS.clarifying_questions![0]] },
      new Error('meloD timed out'),
      DONE,
    ];
    renderAt('/');
    send('@dashboard failed logins');
    const asked = await settledRun(0);
    fireEvent.click(within(card(asked, 'Which time window?')).getByRole('button', { name: /7d/ }));
    const failed = await settledRun(1, 'failed');
    expect(within(failed).getByText(/meloD timed out/)).toBeTruthy();
    const keep = card(failed, 'Your answers are kept');
    expect(within(keep).getByText('7d')).toBeTruthy();

    fireEvent.click(within(keep).getByRole('button', { name: 'Retry with these answers' }));
    await waitFor(() => expect(mock.melodGenerateDashboard).toHaveBeenCalledTimes(3));
    expect(mock.melodGenerateDashboard.mock.calls[2][0]).toEqual(mock.melodGenerateDashboard.mock.calls[1][0]);
    expect(mock.melodGenerateDashboard.mock.calls[2][0]).toEqual({ description: 'failed logins', session_id: 's', answers: { window: '7d' } });
    const preview = await settledRun(2);
    expect(within(preview).getByRole('button', { name: /Save dashboard/ })).toBeTruthy();
  });

  test('Save is idempotent: a save that timed out but went through is reused, not created twice (NAN-4607)', async () => {
    mock.jobResults = [DONE];
    // Before the first attempt: an older dashboard of the same name exists.
    const older = { id: 'dash-old', name: DASH.name, panel_count: 3, visibility: 'private', created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z' };
    mock.listDashboards.mockResolvedValueOnce([older]);
    // The create times out on the client, but the server created it.
    mock.createDashboard.mockRejectedValueOnce(new Error('Request timed out'));
    mock.listDashboards.mockResolvedValueOnce([
      older,
      // The server trims names; the match does too.
      { ...older, id: 'dash-new', name: `${DASH.name}  `, created_at: new Date().toISOString(), updated_at: new Date().toISOString() },
    ]);
    renderAt('/');
    send('@dashboard failed logins by country');
    const run = await settledRun(0);
    const save = card(run, DASH.name);
    fireEvent.click(within(save).getByRole('button', { name: /Save dashboard/ }));
    await waitFor(() => expect(within(save).getByText(/Request timed out/)).toBeTruthy());

    fireEvent.click(within(save).getByRole('button', { name: /Save dashboard/ }));
    await waitFor(() => expect(where).toBe('/dashboards/dash-new'));
    expect(mock.createDashboard).toHaveBeenCalledTimes(1);
    expect(within(save).getByText(/already saved by the earlier attempt/)).toBeTruthy();
  });

  test('Save retry without a "before" list creates again; a new same-name dashboard is never taken for ours (NAN-4607)', async () => {
    mock.jobResults = [DONE];
    mock.listDashboards.mockRejectedValueOnce(new Error('list failed'));
    mock.createDashboard.mockRejectedValueOnce(new Error('Request timed out'));
    const now = new Date().toISOString();
    mock.listDashboards.mockResolvedValue([
      { id: 'dash-theirs', name: DASH.name, panel_count: 3, visibility: 'private', created_at: now, updated_at: now },
    ]);
    mock.createDashboard.mockResolvedValueOnce({ id: 'dash-2', name: DASH.name });
    renderAt('/');
    send('@dashboard failed logins by country');
    const run = await settledRun(0);
    const save = card(run, DASH.name);
    fireEvent.click(within(save).getByRole('button', { name: /Save dashboard/ }));
    await waitFor(() => expect(within(save).getByText(/Request timed out/)).toBeTruthy());

    fireEvent.click(within(save).getByRole('button', { name: /Save dashboard/ }));
    await waitFor(() => expect(where).toBe('/dashboards/dash-2'));
    expect(mock.createDashboard).toHaveBeenCalledTimes(2);
  });

  test('a double click on Save creates one dashboard (NAN-4607)', async () => {
    mock.jobResults = [DONE];
    let resolve: (v: unknown) => void = () => {};
    mock.createDashboard.mockReturnValueOnce(new Promise((r) => { resolve = r; }));
    renderAt('/');
    send('@dashboard failed logins by country');
    const run = await settledRun(0);
    const button = within(card(run, DASH.name)).getByRole('button', { name: /Save dashboard/ });
    fireEvent.click(button);
    fireEvent.click(button);
    await waitFor(() => expect(mock.createDashboard).toHaveBeenCalledTimes(1));
    resolve({ id: 'dash-42', name: DASH.name });
    await waitFor(() => expect(where).toBe('/dashboards/dash-42'));
    expect(mock.createDashboard).toHaveBeenCalledTimes(1);
  });

  test('a required free-text question needs an answer', async () => {
    mock.jobResults = [
      { session_id: 's', message: '', is_complete: false, clarifying_questions: [
        { id: 'svc', question: 'Which service names matter?', question_type: 'free_text', required: true },
      ] },
    ];
    renderAt('/');
    send('@dashboard kerberos service tickets');
    const run = await settledRun(0);
    const q = card(run, 'Which service names matter?');
    expect(within(q).queryByRole('button', { name: /Skip|Use default/ })).toBeNull();
    expect((within(q).getByRole('button', { name: 'Answer' }) as HTMLButtonElement).disabled).toBe(true);
  });

  test('a job failure or an empty result stays in pivt with the reason', async () => {
    mock.jobResults = [new Error('meloD is not configured for this tenant'), { session_id: 's', message: 'There is no auth data in the last 7 days.', is_complete: true }];
    renderAt('/');
    send('@dashboard failed logins');
    const failed = await settledRun(0, 'failed');
    expect(within(failed).getByText('pivt could not generate this dashboard.')).toBeTruthy();
    expect(within(failed).getByText(/not configured/)).toBeTruthy();
    send('@dashboard failed logins again');
    const empty = await settledRun(1, 'failed');
    expect(within(empty).getByText(/no auth data in the last 7 days/)).toBeTruthy();
    expect(where).toBe('/');
  });

  test('bare @dashboard asks for the brief and calls nothing', async () => {
    renderAt('/');
    send('@dashboard ');
    await waitFor(() => expect(pivtInput().value).toBe('@dashboard '));
    expect(mock.melodGenerateDashboard).not.toHaveBeenCalled();
  });
});

describe('Dashboards page entry points', () => {
  test('"Generate with pivt" opens the panel; New Dashboard is the blank dialog (no generator sheet)', async () => {
    renderAt('/dashboards');
    const generate = screen.getAllByRole('button', { name: /Generate with pivt/ });
    expect(generate.length).toBeGreaterThan(0);
    fireEvent.click(generate[0]);
    await waitFor(() => expect(pivtInput().value).toBe('@dashboard '));
    expect(mock.melodGenerateDashboard).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole('button', { name: /^New Dashboard$/ }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).queryByText(/Generate|Describe|Clarify/)).toBeNull();
  });

  test('without the generate permissions there is no pivt entry', () => {
    // melod:chat alone is not enough: the generate endpoint checks
    // melod:dashboard + search:execute (NAN-4607).
    for (const perms of [
      ['dashboards:view', 'dashboards:create', 'melod:chat'],
      ['dashboards:view', 'dashboards:create', 'melod:dashboard'],
    ]) {
      mock.perms = new Set(perms);
      renderAt('/dashboards');
      expect(screen.queryByRole('button', { name: /Generate with pivt/ })).toBeNull();
      expect(screen.getByRole('button', { name: /^New Dashboard$/ })).toBeTruthy();
      cleanup();
    }
  });
});
