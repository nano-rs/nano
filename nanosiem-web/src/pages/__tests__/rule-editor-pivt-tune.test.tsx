// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
//
// NAN-4590 — AI tuning (@tune) and triage hints run in the pivt panel, not in
// a sheet on the rule editor. Through the real pivt shell (PivtShellOverlay →
// PivtPanel → PivtPanelBody → PivtInput → command router) next to the real
// rule editor page:
//   - "AI tune rule" and `@tune` on a rule tune it in pivt: context, analysis,
//     one card per suggestion with a query diff
//   - Apply writes the editor buffer through the rule-editor bridge (unsaved,
//     nothing saved); Dismiss settles the card; "Tune again" re-runs with
//     the analyst's feedback
//   - Apply after leaving the editor opens the rule with the edit applied
//   - tuning off / read-only / unsaved rule / off the editor
//   - Inspector "Generate with pivt" drafts hints in pivt; "Use hints" applies
//   - no dialog or sheet anywhere
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes, useLocation, useNavigate } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import type { Capabilities } from '@/hooks/use-capabilities';
import type { DetectionRule } from '@/lib/api/types';

const RULE_QUERY = 'process_name="powershell.exe" command_line=/.*DownloadString.*/';
const TUNED_QUERY = `${RULE_QUERY} NOT src_host IN ("sccm-01", "sccm-02")`;

const mock = vi.hoisted(() => ({
  perms: new Set(['detections:view', 'detections:edit', 'melod:chat']),
  aiTuning: true,
  tuningMode: 'on' as 'on' | 'off' | 'manual',
  rule: null as unknown as DetectionRule,
  job: {
    hold: false,
    release: null as null | (() => void),
  },
  updateDetection: vi.fn(),
  melodTuneDetection: vi.fn(),
  melodChat: vi.fn(),
  jobResults: [] as unknown[],
  listAlerts: vi.fn(),
  getDetectionMatches: vi.fn(),
  getDetection: vi.fn(),
}));

function caps(): Capabilities {
  return {
    search: true, cases: false, notebooks: false, risk: false, melod: true, queryCorrection: false,
    customEnrichment: false, agentEnrichment: false, aiTuning: mock.aiTuning, playbooks: false, incidents: false,
    siemHealth: true, sso: true, observabilityConvergence: false, iocLists: true, soar: false,
  };
}

// Any API surface the editor's children touch resolves empty; the calls this
// test is about are explicit.
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
    api: autoApi({
      melodTuneDetection: mock.melodTuneDetection,
      melodChat: mock.melodChat,
      listAlerts: mock.listAlerts,
      getDetectionMatches: mock.getDetectionMatches,
      getDetection: mock.getDetection,
      'aiTuning.get': () => Promise.resolve({ ai_tuning_mode: mock.tuningMode }),
    }),
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
    useDetections: () => ({ data: [mock.rule], loading: false, refetch: vi.fn() }),
    useDetection: (id?: string) => ({
      data: id === mock.rule.id ? mock.rule : undefined,
      loading: false,
      refetch: vi.fn(),
    }),
    useUpdateDetection: () => ({ mutate: mock.updateDetection, loading: false }),
  };
});
vi.mock('@/hooks/use-capabilities', async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  useCapabilities: () => ({ edition: 'enterprise', version: 'test', capabilities: caps() }),
}));
// CodeMirror needs layout jsdom lacks; the lens is a plain buffer view here.
vi.mock('@/components/rule-editor/CodeLens', () => ({
  CodeLens: ({ value, onChange }: { value: string; onChange: (v: string) => void }) => (
    <textarea aria-label="Rule YAML" value={value} onChange={(e) => onChange(e.target.value)} />
  ),
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
// The poller has its own tests; here each job settles with the next queued
// result once its start request was sent (optionally held open).
vi.mock('@/enterprise/hooks/use-melod-job', () => ({
  pollMelodJob: async (fn: () => Promise<unknown>, opts?: { onProgress?: (m?: string) => void }) => {
    await fn();
    opts?.onProgress?.('Replaying 30 days of matches');
    if (mock.job.hold) await new Promise<void>((r) => (mock.job.release = r));
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
import type { PivtWizardNavState } from '@/enterprise/components/pivt/commands/router';
import { RuleEditorRedesign } from '../RuleEditorRedesign';

function rule(overrides: Partial<DetectionRule> = {}): DetectionRule {
  return {
    id: 'r1',
    name: 'powershell_download_cradle',
    description: 'PowerShell download cradle',
    query: RULE_QUERY,
    severity: 'high',
    mode: 'alerting',
    detection_mode: 'scheduled',
    schedule_cron: '* * * * *',
    lookback_minutes: 5,
    mitre_tactics: ['execution'],
    mitre_techniques: ['T1059.001'],
    tags: [],
    created_at: '2026-10-01T00:00:00Z',
    updated_at: '2026-10-20T00:00:00Z',
    match_count: 42,
    ...overrides,
  };
}

const tuned = {
  session_id: 's1',
  message: '',
  detection: {
    name: 'powershell_download_cradle',
    description: '',
    query: RULE_QUERY,
    severity: 'high',
    mitre_tactics: [],
    mitre_techniques: [],
    historical_analysis: { total_matches: 412, days_analyzed: 30, daily_average: 13.7 },
    noise_assessment: {
      level: 'high',
      daily_average: 13.7,
      peak_daily_matches: 40,
      estimated_daily_alerts: 13,
      alert_fatigue_risk: 'high',
      explanation: 'Most matches come from the two SCCM servers during patch windows.',
      threshold_suggestions: [],
    },
    tuning_suggestions: [
      {
        issue: 'SCCM servers trigger this nightly',
        suggestion: 'Exclude the SCCM distribution points.',
        modified_query: TUNED_QUERY,
      },
      { issue: 'Matches cluster in patch windows', suggestion: 'Consider a schedule exclusion for Tuesday nights.' },
    ],
  },
};

let where: { pathname: string; state: unknown } = { pathname: '', state: null };
let nav: ReturnType<typeof useNavigate> | null = null;
function Where() {
  const loc = useLocation();
  where = { pathname: loc.pathname, state: loc.state };
  nav = useNavigate();
  return <div data-testid="where">{loc.pathname}</div>;
}

function Shell() {
  const pivt = usePivtState();
  return (
    <PivtShellOverlay state={pivt}>
      <Where />
      <Routes>
        <Route path="/" element={<div>home</div>} />
        <Route path="/rules/tuning" element={<div>tuning queue</div>} />
        <Route path="/rules/editor/new" element={<RuleEditorRedesign />} />
        <Route path="/rules/editor/:id" element={<RuleEditorRedesign />} />
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

function pivtInput() {
  return screen.getByLabelText('Message pivt') as HTMLTextAreaElement;
}

function send(text: string) {
  const input = pivtInput();
  fireEvent.change(input, { target: { value: text } });
  fireEvent.keyDown(input, { key: 'Enter' });
}

function buffer() {
  return (screen.getByLabelText('Rule YAML') as HTMLTextAreaElement).value;
}

async function settledRun(index = 0, status = 'done') {
  await waitFor(() => expect(screen.getAllByTestId('pivt-draft-run').length).toBeGreaterThan(index));
  const run = screen.getAllByTestId('pivt-draft-run')[index];
  await waitFor(() => expect(run.getAttribute('data-status')).toBe(status));
  return run;
}

function card(run: HTMLElement, title: string) {
  const el = within(run)
    .getAllByTestId('pivt-run-card')
    .find((c) => within(c).queryByText(title));
  if (!el) throw new Error(`no card ${title}`);
  return el;
}

beforeEach(() => {
  localStorage.clear();
  localStorage.setItem('nano-pivt-open', '1');
  resetPivtDraftStore();
  resetRunActions();
  mock.perms = new Set(['detections:view', 'detections:edit', 'melod:chat']);
  mock.aiTuning = true;
  mock.tuningMode = 'on';
  mock.rule = rule();
  mock.job.hold = false;
  mock.job.release = null;
  mock.jobResults = [];
  for (const fn of [mock.updateDetection, mock.melodTuneDetection, mock.melodChat, mock.listAlerts, mock.getDetectionMatches, mock.getDetection]) {
    fn.mockReset();
  }
  mock.melodTuneDetection.mockResolvedValue({ job_id: 'j1', status: 'pending' });
  mock.melodChat.mockResolvedValue({ job_id: 'j2', status: 'pending' });
  mock.listAlerts.mockResolvedValue([
    { id: 'a1', disposition: 'false_positive' },
    { id: 'a2', disposition: 'false_positive' },
    { id: 'a3' },
  ]);
  mock.getDetectionMatches.mockResolvedValue({ total: 412, matches: [{ id: 'm1', event_count: 1 }, { id: 'm2', event_count: 3 }] });
  mock.getDetection.mockImplementation(async () => mock.rule);
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

describe('pivt tunes the rule in its panel', () => {
  test('"AI tune rule" tunes in pivt; Apply writes the editor buffer, unsaved, no sheet', async () => {
    mock.jobResults = [tuned];
    mock.job.hold = true;
    renderAt('/rules/editor/r1');
    await waitFor(() => expect(buffer()).toContain(RULE_QUERY));

    const menu = screen.getByRole('button', { name: 'Rule actions' });
    fireEvent.pointerDown(menu, { button: 0, ctrlKey: false });
    fireEvent.click(await screen.findByRole('menuitem', { name: /AI tune rule/ }));

    await waitFor(() => expect(mock.melodTuneDetection).toHaveBeenCalledWith({ rule_id: 'r1', feedback: undefined }));
    const running = await settledRun(0, 'running');
    expect(within(running).getByText('Tuning this rule…')).toBeTruthy();
    expect(within(running).getByText('Tune powershell_download_cradle')).toBeTruthy();
    expect(within(running).getAllByText('Read 3 recent alerts (2 false positive) and 2 matches').length).toBeGreaterThan(0);
    expect(mock.listAlerts).toHaveBeenCalledWith({ rule_id: 'r1', limit: 20 });
    act(() => mock.job.release?.());

    const run = await settledRun();
    const panel = within(run);
    expect(panel.getByText('3 recent · 2 FP')).toBeTruthy();
    expect(panel.getByText('412 in 30d · 13.7/day')).toBeTruthy();
    expect(panel.getByText('high · high fatigue risk')).toBeTruthy();
    expect(panel.getByText(/Most matches come from the two SCCM servers/)).toBeTruthy();

    const sccm = card(run, 'SCCM servers trigger this nightly');
    // Diff preview: the exclusion is the added line, the old query removed.
    const diff = within(sccm).getByTestId('pivt-diff');
    expect(diff.querySelector('[data-diff="add"]')?.textContent).toContain('NOT src_host IN');
    expect(diff.querySelector('[data-diff="del"]')?.textContent).toContain('DownloadString');
    // A suggestion without a query can only be dismissed.
    const schedule = card(run, 'Matches cluster in patch windows');
    expect(within(schedule).queryByRole('button', { name: /Apply to editor/ })).toBeNull();

    fireEvent.click(within(sccm).getByRole('button', { name: /Apply to editor/ }));
    await waitFor(() => expect(sccm.getAttribute('data-state')).toBe('applied'));
    expect(within(sccm).getByText(/Applied to the editor, unsaved/)).toBeTruthy();
    expect(buffer()).toContain(TUNED_QUERY);
    // Frontmatter survives: only the query changed.
    expect(buffer()).toContain('powershell_download_cradle');
    expect(mock.updateDetection).not.toHaveBeenCalled();
    expect(screen.getByTestId('where').textContent).toBe('/rules/editor/r1');
    expect(screen.queryByRole('dialog')).toBeNull();

    fireEvent.click(within(schedule).getByRole('button', { name: /Dismiss/ }));
    await waitFor(() => expect(schedule.getAttribute('data-state')).toBe('rejected'));
  });

  test('@tune <feedback> sends the feedback; "Tune again" re-runs with new feedback', async () => {
    mock.jobResults = [tuned, tuned];
    renderAt('/rules/editor/r1');
    await waitFor(() => expect(buffer()).toContain(RULE_QUERY));
    send('@tune the SCCM boxes are expected');
    await waitFor(() =>
      expect(mock.melodTuneDetection).toHaveBeenCalledWith({ rule_id: 'r1', feedback: 'the SCCM boxes are expected' }),
    );
    const run = await settledRun();
    expect(within(run).getByText('Tune powershell_download_cradle: the SCCM boxes are expected')).toBeTruthy();

    const again = card(run, 'Still noisy? Tell pivt what you see');
    const button = within(again).getByRole('button', { name: 'Tune again' }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    fireEvent.change(within(again).getByLabelText('Feedback for pivt'), { target: { value: 'also jump hosts' } });
    fireEvent.click(button);
    await waitFor(() => expect(again.getAttribute('data-state')).toBe('answered'));
    await waitFor(() => expect(mock.melodTuneDetection).toHaveBeenLastCalledWith({ rule_id: 'r1', feedback: 'also jump hosts' }));
    await settledRun(1);
  });

  test('Apply after leaving the editor opens the rule with the query applied', async () => {
    mock.jobResults = [tuned];
    renderAt('/rules/editor/r1');
    await waitFor(() => expect(buffer()).toContain(RULE_QUERY));
    send('@tune ');
    const run = await settledRun();
    act(() => nav?.('/'));
    await waitFor(() => expect(screen.getByTestId('where').textContent).toBe('/'));

    fireEvent.click(within(card(run, 'SCCM servers trigger this nightly')).getByRole('button', { name: /Apply to editor/ }));
    await waitFor(() => expect(screen.getByTestId('where').textContent).toBe('/rules/editor/r1'));
    await waitFor(() => expect(buffer()).toContain(TUNED_QUERY));
    expect(within(run).getByText(/Opened the rule with this query applied/)).toBeTruthy();
    // The carried edit is consumed once.
    await waitFor(() => expect(where.state).toBeNull());
    expect(mock.updateDetection).not.toHaveBeenCalled();
  });

  test('tuning turned off tenant-wide is explained in pivt; no job runs', async () => {
    mock.tuningMode = 'off';
    renderAt('/rules/editor/r1');
    await waitFor(() => expect(buffer()).toContain(RULE_QUERY));
    send('@tune ');
    const run = await settledRun(0, 'failed');
    expect(within(run).getByText('pivt could not tune this rule.')).toBeTruthy();
    expect(within(run).getByText(/AI tuning is turned off for this tenant/)).toBeTruthy();
    expect(mock.melodTuneDetection).not.toHaveBeenCalled();
  });

  test('read-only analysts get no Tune action and @tune explains why', async () => {
    mock.perms.delete('detections:edit');
    renderAt('/rules/editor/r1');
    await waitFor(() => expect(buffer()).toContain(RULE_QUERY));
    fireEvent.pointerDown(screen.getByRole('button', { name: 'Rule actions' }), { button: 0, ctrlKey: false });
    await screen.findAllByRole('menuitem');
    expect(screen.queryByRole('menuitem', { name: /AI tune rule/ })).toBeNull();
    fireEvent.keyDown(document.activeElement ?? document.body, { key: 'Escape' });
    send('@tune ');
    const run = await settledRun(0, 'failed');
    expect(within(run).getByText(/read-only access/)).toBeTruthy();
    expect(mock.melodTuneDetection).not.toHaveBeenCalled();
  });

  test('a job failure is shown in pivt and leaves the buffer alone', async () => {
    mock.jobResults = [new Error('AI provider not configured')];
    renderAt('/rules/editor/r1');
    await waitFor(() => expect(buffer()).toContain(RULE_QUERY));
    send('@tune ');
    const run = await settledRun(0, 'failed');
    expect(within(run).getByText('AI provider not configured')).toBeTruthy();
    expect(within(run).getByText('The rule is unchanged.')).toBeTruthy();
    expect(buffer()).not.toContain('NOT src_host');
  });

  test('@tune on an unsaved new rule asks to save first', async () => {
    renderAt('/rules/editor/new');
    send('@tune ');
    const run = await settledRun(0, 'failed');
    expect(within(run).getByText(/Save this rule first/)).toBeTruthy();
    expect(mock.melodTuneDetection).not.toHaveBeenCalled();
  });

  test('@tune off the editor opens the tuning queue with the brief in router state', async () => {
    renderAt('/');
    send('@tune noisy powershell rules');
    await waitFor(() => expect(screen.getByTestId('where').textContent).toBe('/rules/tuning'));
    expect((where.state as PivtWizardNavState).pivtWizard.prompt).toBe('noisy powershell rules');
    expect(screen.queryByTestId('pivt-draft-run')).toBeNull();
  });
});

describe('pivt drafts triage hints in its panel', () => {
  const hintsReply = {
    session_id: 's2',
    message:
      'Here you go:\n{"ignore_when": ["Parent is the SCCM client (CcmExec.exe)"], "suspicious_when": ["Download target is a raw IP", "User is not an admin"], "context": "Cradles are common in red-team tooling."}',
  };

  async function openHints() {
    await waitFor(() => expect(buffer()).toContain(RULE_QUERY));
    // Saved rules start with the inspector collapsed.
    fireEvent.click(screen.getByRole('button', { name: 'Expand inspector' }));
    return screen.findByRole('button', { name: /Generate with pivt/ });
  }

  test('"Generate with pivt" drafts in the panel; "Use hints" fills the Hints tab, unsaved', async () => {
    mock.jobResults = [hintsReply];
    renderAt('/rules/editor/r1');
    fireEvent.click(await openHints());
    await waitFor(() => expect(mock.melodChat).toHaveBeenCalledTimes(1));
    expect(mock.melodChat.mock.calls[0][0].message).toContain(RULE_QUERY);
    const run = await settledRun();
    expect(within(run).getByText('Draft triage hints for powershell_download_cradle')).toBeTruthy();
    const hints = card(run, 'Triage hints');
    expect(within(hints).getByText('Download target is a raw IP')).toBeTruthy();

    fireEvent.click(within(hints).getByRole('button', { name: /Use hints/ }));
    await waitFor(() => expect(hints.getAttribute('data-state')).toBe('applied'));
    // The inspector now lists them as conditions (two places: pivt card + editor).
    expect(screen.getAllByText('Parent is the SCCM client (CcmExec.exe)').length).toBe(2);
    expect(screen.getByRole('button', { name: /Regenerate with pivt/ })).toBeTruthy();
    expect(mock.updateDetection).not.toHaveBeenCalled();
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  test('an unparseable reply is a failed run; hints stay as they were', async () => {
    mock.jobResults = [{ session_id: 's2', message: 'Sorry, I cannot help with that.' }];
    renderAt('/rules/editor/r1');
    fireEvent.click(await openHints());
    const run = await settledRun(0, 'failed');
    expect(within(run).getByText('pivt replied without usable hints. Try again.')).toBeTruthy();
    expect(screen.getByRole('button', { name: /Generate with pivt/ })).toBeTruthy();
  });
});
