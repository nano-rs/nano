// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
//
// NAN-4595 — pivt drafts detection rules inline in its panel (no editor
// aside). Through the real pivt shell (PivtShellOverlay → PivtPanel →
// PivtPanelBody → PivtInput → command router) next to the real Rules list and
// rule editor:
//   - `@detection <narrative>` and "create a detection for …" draft candidates
//   - each candidate is a card; "Open in editor" lands the rule in the
//     new-rule editor through the rule-editor bridge (unsaved)
//   - "Create N" creates the remaining candidates in staging and opens the
//     rule list filtered to them; dismissing a candidate updates N
//   - failures are shown in pivt; nothing opens a dialog
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import type { Capabilities } from '@/hooks/use-capabilities';
import type { DetectionRule, GeneratedDetection } from '@/lib/api/types';

const mock = vi.hoisted(() => ({
  perms: new Set(['detections:view', 'detections:edit', 'detections:create', 'melod:chat']),
  rules: [] as DetectionRule[],
  jobResults: [] as unknown[],
  melodCreateDetection: vi.fn(),
  createDetection: vi.fn(),
  updateDetection: vi.fn(),
}));

function caps(): Capabilities {
  return {
    search: true, cases: false, notebooks: false, risk: false, melod: true, queryCorrection: false,
    customEnrichment: false, agentEnrichment: false, aiTuning: true, playbooks: false, incidents: false,
    siemHealth: true, sso: true, observabilityConvergence: false, iocLists: true, soar: false,
  };
}

// Any API surface the pages touch resolves empty; the calls under test are explicit.
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
    api: autoApi({ melodCreateDetection: mock.melodCreateDetection, createDetection: mock.createDetection }),
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
    useDetections: () => ({ data: mock.rules, loading: false, refetch: vi.fn() }),
    useDetection: () => ({ data: undefined, loading: false, refetch: vi.fn() }),
    useUpdateDetection: () => ({ mutate: mock.updateDetection, loading: false }),
  };
});
vi.mock('@/hooks/use-capabilities', async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  useCapabilities: () => ({ edition: 'enterprise', version: 'test', capabilities: caps() }),
}));
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
vi.mock('@/enterprise/hooks/use-melod-job', () => ({
  pollMelodJob: async (fn: () => Promise<unknown>, opts?: { onProgress?: (m?: string) => void }) => {
    await fn();
    opts?.onProgress?.('Validating candidate queries');
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
import { Rules } from '../Rules';
import { RuleEditorRedesign } from '../RuleEditorRedesign';

const KERB = 'create a detection for kerberoasting from non-service accounts';

function candidate(name: string, query: string, over: Partial<GeneratedDetection> = {}): GeneratedDetection {
  return {
    name,
    description: `Detects ${name.replace(/_/g, ' ')}`,
    query,
    severity: 'high',
    mitre_tactics: ['credential-access'],
    mitre_techniques: ['T1558.003'],
    ...over,
  };
}

const CANDIDATES = [
  candidate('kerberoast_rc4_tgs_requests', 'event_id=4769 ticket_encryption_type="0x17" NOT user=/svc_.*/'),
  candidate('kerberoast_tgs_burst_per_user', 'event_id=4769 | stats dc(service_name) as svcs by user | where svcs > 10', {
    severity: 'medium',
  }),
  candidate('kerberoast_honey_spn', 'event_id=4769 service_name="svc_honey_sql"', { severity: 'critical' }),
];

function rule(id: string, name: string, mode: DetectionRule['mode'] = 'staging'): DetectionRule {
  return {
    id, name, query: 'x', severity: 'high', mode, mitre_tactics: [], mitre_techniques: [], tags: [],
    created_at: '2026-10-26T00:00:00Z', updated_at: '2026-10-26T00:00:00Z', match_count: 0,
  };
}

let where = '';
function Where() {
  const loc = useLocation();
  where = `${loc.pathname}${loc.search}`;
  return <div data-testid="where">{where}</div>;
}

function Shell() {
  const pivt = usePivtState();
  return (
    <PivtShellOverlay state={pivt}>
      <Where />
      <Routes>
        <Route path="/" element={<div>home</div>} />
        <Route path="/rules" element={<Rules />} />
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

const pivtInput = () => screen.getByLabelText('Message pivt') as HTMLTextAreaElement;
function send(text: string) {
  fireEvent.change(pivtInput(), { target: { value: text } });
  fireEvent.keyDown(pivtInput(), { key: 'Enter' });
}
const buffer = () => (screen.getByLabelText('Rule YAML') as HTMLTextAreaElement).value;

async function settledRun(status = 'done') {
  const run = await screen.findByTestId('pivt-draft-run');
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
  mock.perms = new Set(['detections:view', 'detections:edit', 'detections:create', 'melod:chat']);
  mock.rules = [rule('r-old', 'legacy_rule_one', 'alerting')];
  mock.jobResults = [];
  mock.melodCreateDetection.mockReset().mockResolvedValue({ job_id: 'j1', status: 'pending' });
  mock.createDetection.mockReset();
  mock.updateDetection.mockReset();
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

describe('pivt drafts detections in its panel', () => {
  test('free text drafts with the whole sentence; candidates are cards; Open in editor fills the new-rule editor, unsaved', async () => {
    mock.jobResults = [{ session_id: 's', message: '', detections: CANDIDATES }];
    renderAt('/');
    send(KERB);
    await waitFor(() => expect(mock.melodCreateDetection).toHaveBeenCalledWith({ description: KERB }));
    const run = await settledRun();
    expect(within(run).getByText(KERB)).toBeTruthy();
    expect(within(run).getByText(/3 candidate rules/)).toBeTruthy();
    const rc4 = card(run, 'kerberoast_rc4_tgs_requests');
    expect(within(rc4).getByText('high')).toBeTruthy();
    expect(within(rc4).getByText('credential-access, T1558.003')).toBeTruthy();
    expect(within(rc4).getByText(CANDIDATES[0].query)).toBeTruthy();
    expect(within(card(run, 'Create 3 rules in staging')).getByRole('button', { name: 'Create 3' })).toBeTruthy();

    fireEvent.click(within(rc4).getByRole('button', { name: /Open in editor/ }));
    await waitFor(() => expect(where).toBe('/rules/editor/new'));
    await waitFor(() => expect(buffer()).toContain('title: kerberoast_rc4_tgs_requests'));
    expect(buffer()).toContain(CANDIDATES[0].query);
    expect(buffer()).toContain('mode: staging');
    // The editor fills what the draft leaves to it.
    expect(buffer()).toContain('author: Dan Lussier');
    expect(buffer()).toContain('detection_mode: scheduled');
    await waitFor(() => expect(rc4.getAttribute('data-state')).toBe('applied'));
    expect(within(rc4).getByText(/Opened in the new-rule editor, unsaved/)).toBeTruthy();
    // The opened candidate leaves the batch.
    expect(within(run).getByRole('button', { name: 'Create 2' })).toBeTruthy();
    expect(mock.createDetection).not.toHaveBeenCalled();
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  test('on the new-rule editor, Open in editor replaces the buffer in place; no aside opens', async () => {
    mock.jobResults = [{ session_id: 's', message: '', detection: CANDIDATES[2] }];
    renderAt('/rules/editor/new');
    await waitFor(() => expect(buffer()).toContain('title:'));
    expect(screen.queryByText('AI generation')).toBeNull();
    expect(screen.queryByLabelText('Close AI generation')).toBeNull();
    send('@detection access to the honey SPN svc_honey_sql');
    const run = await settledRun();
    expect(within(run).getByText(/One candidate rule/)).toBeTruthy();
    // A single candidate has no batch card.
    expect(within(run).queryByText(/in staging/)).toBeNull();
    fireEvent.click(within(card(run, 'kerberoast_honey_spn')).getByRole('button', { name: /Open in editor/ }));
    await waitFor(() => expect(buffer()).toContain('svc_honey_sql'));
    expect(buffer()).toContain('severity: critical');
    expect(where).toBe('/rules/editor/new');
  });

  test('Create N creates the remaining candidates in staging and opens the list filtered to them', async () => {
    mock.jobResults = [{ session_id: 's', message: '', detections: CANDIDATES }];
    let n = 0;
    mock.createDetection.mockImplementation(async (req: { name: string }) => {
      n += 1;
      const created = rule(`r-new-${n}`, req.name);
      mock.rules = [...mock.rules, created];
      return created;
    });
    renderAt('/rules');
    expect(await screen.findByText('legacy_rule_one')).toBeTruthy();
    send(`@detection ${KERB}`);
    const run = await settledRun();

    fireEvent.click(within(card(run, 'kerberoast_tgs_burst_per_user')).getByRole('button', { name: /Dismiss/ }));
    await waitFor(() => expect(within(run).getByRole('button', { name: 'Create 2' })).toBeTruthy());
    fireEvent.click(within(run).getByRole('button', { name: 'Create 2' }));

    await waitFor(() => expect(mock.createDetection).toHaveBeenCalledTimes(2));
    expect(mock.createDetection.mock.calls.map((c) => c[0].name)).toEqual(['kerberoast_rc4_tgs_requests', 'kerberoast_honey_spn']);
    expect(mock.createDetection.mock.calls[0][0]).toMatchObject({
      mode: 'staging',
      detection_mode: 'scheduled',
      schedule_cron: '* * * * *',
      severity: 'high',
      ai_generated: true,
      mitre_techniques: ['T1558.003'],
    });
    await waitFor(() => expect(where).toBe('/rules?ids=r-new-1,r-new-2'));
    const batch = card(run, 'Create 2 rules in staging');
    await waitFor(() => expect(batch.getAttribute('data-state')).toBe('applied'));
    expect(within(batch).getByText(/Created 2 staging rules and opened the rule list/)).toBeTruthy();
    expect(card(run, 'kerberoast_rc4_tgs_requests').getAttribute('data-state')).toBe('applied');
    expect(card(run, 'kerberoast_tgs_burst_per_user').getAttribute('data-state')).toBe('rejected');
  });

  test('a partial create failure is reported on the card and the candidate', async () => {
    mock.jobResults = [{ session_id: 's', message: '', detections: CANDIDATES.slice(0, 2) }];
    mock.createDetection
      .mockResolvedValueOnce(rule('r-new-1', CANDIDATES[0].name))
      .mockRejectedValueOnce(new Error('query does not parse: unknown field svcs'));
    renderAt('/');
    send(`@detection ${KERB}`);
    const run = await settledRun();
    fireEvent.click(within(run).getByRole('button', { name: 'Create 2' }));
    await waitFor(() => expect(where).toBe('/rules?ids=r-new-1'));
    expect(await within(run).findByText(/Not created: kerberoast_tgs_burst_per_user: query does not parse/)).toBeTruthy();
    expect(card(run, 'kerberoast_tgs_burst_per_user').getAttribute('data-state')).toBe('failed');
  });

  test('the filtered rule list shows only pivt-created rules until cleared', async () => {
    mock.rules = [rule('r-old', 'legacy_rule_one', 'alerting'), rule('r-new-1', 'kerberoast_rc4_tgs_requests')];
    renderAt('/rules?ids=r-new-1');
    expect(await screen.findByText('kerberoast_rc4_tgs_requests')).toBeTruthy();
    expect(screen.queryByText('legacy_rule_one')).toBeNull();
    expect(screen.getByText(/from pivt/)).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Show all rules' }));
    expect(await screen.findByText('legacy_rule_one')).toBeTruthy();
    expect(where).toBe('/rules');
  });

  test('Rules → Draft with pivt opens pivt with @detection focused', async () => {
    renderAt('/rules');
    fireEvent.click(await screen.findByRole('button', { name: 'Draft with pivt' }));
    await waitFor(() => expect(pivtInput().value).toBe('@detection '));
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  test('Draft with pivt is hidden without detections:create or melod:chat', async () => {
    for (const perm of ['detections:create', 'melod:chat']) {
      mock.perms = new Set(['detections:view', 'detections:edit', 'detections:create', 'melod:chat']);
      mock.perms.delete(perm);
      renderAt('/rules');
      expect(await screen.findByText('legacy_rule_one')).toBeTruthy();
      expect(screen.queryByRole('button', { name: 'Draft with pivt' })).toBeNull();
      cleanup();
    }
  });

  test('a failed draft is shown in pivt; nothing is created', async () => {
    mock.jobResults = [new Error('AI provider not configured')];
    renderAt('/');
    send(`@detection ${KERB}`);
    const run = await settledRun('failed');
    expect(within(run).getByText('pivt could not draft detections.')).toBeTruthy();
    expect(within(run).getByText('AI provider not configured')).toBeTruthy();
    expect(mock.createDetection).not.toHaveBeenCalled();
  });

  test('no candidates is a failed run', async () => {
    mock.jobResults = [{ session_id: 's', message: 'hm', detections: [] }];
    renderAt('/');
    send(`@detection ${KERB}`);
    const run = await settledRun('failed');
    expect(within(run).getByText(/returned no candidate rules/)).toBeTruthy();
  });

  test('a bare @detection asks for the narrative', async () => {
    renderAt('/');
    send('@detection ');
    await waitFor(() => expect(pivtInput().value).toBe('@detection '));
    expect(screen.queryByTestId('pivt-draft-run')).toBeNull();
    expect(mock.melodCreateDetection).not.toHaveBeenCalled();
  });
});
