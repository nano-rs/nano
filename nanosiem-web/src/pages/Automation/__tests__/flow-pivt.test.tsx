// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
//
// NAN-4535 / NAN-4588 — pivt drafts SOAR flows inline in its panel. These run
// through the real pivt shell (PivtShellOverlay → PivtPanel → PivtPanelBody →
// PivtInput → command router) next to the real Automation routes:
//   - typed text is never collapsed by the suggestion-label mapper; a clear
//     "create a flow" request carries the whole sentence as the brief
//   - questions / listings stay chat
//   - success shows a summary in pivt and navigates to the saved (disabled)
//     draft; failure shows the error in pivt; no modal either way
//   - Flows → "Draft with pivt" opens pivt with `@flow ` focused
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import type { Capabilities } from '@/hooks/use-capabilities';
import { PIVT_COMMANDS } from '@/enterprise/components/pivt/commands/registry';
import { suggestionToCommand } from '@/enterprise/components/pivt/commands/parse';
import { PIVT_CHAT_MESSAGE_EVENT } from '@/enterprise/components/pivt/commands/router';
import { PivtShellOverlay } from '@/enterprise/components/pivt/PivtShellOverlay';
import { resetPivtDraftStore } from '@/enterprise/components/pivt/drafts/draft-store';
import { usePivtState } from '@/enterprise/hooks/use-pivt-state';
import { catalog, connection, flow, settings } from './fixtures';

const DAN =
  'I want to create an automation flow that will check for a high sev alert, then search up important entities in npl search';

const mock = vi.hoisted(() => ({
  melod: true,
  perms: new Set(['soar:view', 'soar:run', 'soar:manage', 'melod:chat']),
  job: {
    outcome: { kind: 'ok' } as { kind: 'ok'; value?: unknown } | { kind: 'fail'; message: string },
    release: null as null | (() => void),
    hold: false,
  },
  soarApi: {
    getSettings: vi.fn(),
    getRuns: vi.fn(),
    getCatalog: vi.fn(),
    getConnections: vi.fn(),
    getFlows: vi.fn(),
    getFlow: vi.fn(),
    getFlowStats: vi.fn(),
    validateFlow: vi.fn(),
    updateFlow: vi.fn(),
    queueFlow: vi.fn(),
  },
  melodDraftFlow: vi.fn(),
}));

function caps(): Capabilities {
  return {
    search: true, cases: false, notebooks: false, risk: false, melod: mock.melod, queryCorrection: false,
    customEnrichment: false, agentEnrichment: false, aiTuning: false, playbooks: false, incidents: false,
    siemHealth: true, sso: true, observabilityConvergence: false, iocLists: true, soar: true,
  };
}

vi.mock('@/lib/api', () => ({ api: { soar: mock.soarApi, melodDraftFlow: mock.melodDraftFlow } }));
vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({ edition: 'enterprise', version: 'test', capabilities: caps() }),
}));
vi.mock('@/hooks/use-api', () => ({ useMelodStatus: () => ({ data: { connected: true } }) }));
// The "End investigation" dialog is Cases-coupled (needs NotebookProvider);
// drafts never touch it.
vi.mock('@/enterprise/components/pivt/PivtCloseDialog', () => ({ PivtCloseDialog: () => null }));
vi.mock('@/components/threat-intel/use-threat-intel', () => ({ useEnrichEnabled: () => false }));
vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({
    hasPermission: (p: string) => mock.perms.has(p),
    hasAnyPermission: (ps: string[]) => ps.some((p) => mock.perms.has(p)),
    isDemoUser: false,
    user: { id: 'me', name: 'Dan Lussier' },
  }),
}));
// The poller has its own tests; here the job settles once the start request
// was sent (optionally held open to observe the in-flight panel state).
vi.mock('@/enterprise/hooks/use-melod-job', () => ({
  pollMelodJob: async (
    fn: () => Promise<unknown>,
    opts?: { onProgress?: (m?: string) => void; signal?: AbortSignal },
  ) => {
    await fn();
    opts?.onProgress?.('Validating against your catalog');
    if (mock.job.hold) await new Promise<void>((r) => (mock.job.release = r));
    const outcome = mock.job.outcome;
    if (outcome.kind === 'fail') throw new Error(outcome.message);
    return outcome.value;
  },
}));

import { AutomationFlowRoute, AutomationFlowsRoute } from '../index';

function Where() {
  const loc = useLocation();
  return <div data-testid="where">{loc.pathname}</div>;
}

function Shell() {
  const pivt = usePivtState();
  return (
    <PivtShellOverlay state={pivt}>
      <Where />
      <Routes>
        <Route path="/" element={<div>home</div>} />
        <Route path="/automation/flows" element={<AutomationFlowsRoute />} />
        <Route path="/automation/flows/:id" element={<AutomationFlowRoute />} />
      </Routes>
    </PivtShellOverlay>
  );
}

function renderAt(path: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <Shell />
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

const noFlows = { flows: [], event_overflow_count: 0, last_event_overflow_at: null, admission_backpressure: null };
const created = {
  flow_id: 'f0000000-0000-4000-8000-000000000009',
  name: 'High-sev alert entity hunt',
  version: 1,
  status: 'draft',
  trigger: { on: 'alert', match: 'severity >= high' },
  module_count: 4,
  approval_gates: 1,
  repaired: false,
};

beforeEach(() => {
  localStorage.clear();
  resetPivtDraftStore();
  mock.melod = true;
  mock.perms = new Set(['soar:view', 'soar:run', 'soar:manage', 'melod:chat']);
  mock.job.outcome = { kind: 'ok', value: created };
  mock.job.hold = false;
  mock.job.release = null;
  for (const fn of Object.values(mock.soarApi)) fn.mockReset();
  mock.melodDraftFlow.mockReset();
  mock.melodDraftFlow.mockResolvedValue({ job_id: 'j1', status: 'pending' });
  mock.soarApi.getSettings.mockResolvedValue(settings(true));
  mock.soarApi.getCatalog.mockResolvedValue(catalog());
  mock.soarApi.getConnections.mockResolvedValue({ connections: [connection()] });
  mock.soarApi.getRuns.mockResolvedValue({ runs: [], limit: 100, offset: 0 });
  mock.soarApi.getFlows.mockResolvedValue(noFlows);
  mock.soarApi.getFlowStats.mockResolvedValue({ flows: [] });
  mock.soarApi.getFlow.mockResolvedValue(flow({ id: created.flow_id, name: created.name, status: 'draft', version: 1 }));
});
afterEach(cleanup);

describe('pivt drafts flows inline', () => {
  test("Dan's sentence drafts a flow with the full brief, summarizes in pivt, and opens the draft", async () => {
    renderAt('/');
    send(DAN);
    await waitFor(() => expect(mock.melodDraftFlow).toHaveBeenCalledWith({ brief: DAN }));

    const run = await screen.findByTestId('pivt-draft-run');
    await waitFor(() => expect(run.getAttribute('data-status')).toBe('done'));
    const panel = within(run);
    // The brief is shown verbatim as the analyst's turn.
    expect(panel.getByText(DAN)).toBeTruthy();
    expect(panel.getByText(created.name)).toBeTruthy();
    expect(panel.getByText('saved disabled')).toBeTruthy();
    expect(panel.getByText('1 gate')).toBeTruthy();
    expect(panel.getByText('4')).toBeTruthy();
    expect(panel.getByRole('link', { name: /Open flow/ }).getAttribute('href')).toBe(`/automation/flows/${created.flow_id}`);

    // Navigated to the saved draft, which the flow view labels; pivt stays open.
    await waitFor(() => expect(screen.getByTestId('where').textContent).toBe(`/automation/flows/${created.flow_id}`));
    expect(await screen.findByText('Drafted by pivt')).toBeTruthy();
    expect(localStorage.getItem('nano-pivt-open')).toBe('1');
    // No modal, and the draft was never enabled or run.
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(mock.soarApi.updateFlow).not.toHaveBeenCalled();
    expect(mock.soarApi.queueFlow).not.toHaveBeenCalled();
  });

  test('progress renders in pivt while the job runs', async () => {
    mock.job.hold = true;
    renderAt('/');
    send('@flow contain hosts on critical EDR alerts');
    const run = await screen.findByTestId('pivt-draft-run');
    expect(run.getAttribute('data-status')).toBe('running');
    expect(within(run).getByText('Drafting a flow…')).toBeTruthy();
    expect(await within(run).findAllByText('Validating against your catalog')).not.toHaveLength(0);
    act(() => mock.job.release?.());
    await waitFor(() => expect(run.getAttribute('data-status')).toBe('done'));
  });

  test.each(['why did this flow fail', 'show me dashboards', 'how do I create a flow?'])(
    '"%s" stays chat — no draft, no navigation',
    async (text) => {
      const chat = vi.fn();
      const onChat = (e: Event) => chat((e as CustomEvent<{ text: string }>).detail.text);
      window.addEventListener(PIVT_CHAT_MESSAGE_EVENT, onChat);
      try {
        renderAt('/');
        send(text);
        await waitFor(() => expect(chat).toHaveBeenCalledWith(text));
        expect(mock.melodDraftFlow).not.toHaveBeenCalled();
        expect(screen.queryByTestId('pivt-draft-run')).toBeNull();
        expect(screen.getByTestId('where').textContent).toBe('/');
      } finally {
        window.removeEventListener(PIVT_CHAT_MESSAGE_EVENT, onChat);
      }
    },
  );

  test('a failed draft shows the error in pivt, saves nothing, and opens no modal', async () => {
    mock.job.outcome = {
      kind: 'fail',
      message: 'No installed pack provides `edr.contain_host`. Install the CrowdStrike pack and add a connection.',
    };
    renderAt('/');
    send(DAN);
    const run = await screen.findByTestId('pivt-draft-run');
    await waitFor(() => expect(run.getAttribute('data-status')).toBe('failed'));
    expect(within(run).getByText('pivt could not draft this flow.')).toBeTruthy();
    expect(within(run).getByText(/No installed pack provides/)).toBeTruthy();
    expect(screen.getByTestId('where').textContent).toBe('/');
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  test('meloD unavailable at start is reported in pivt', async () => {
    mock.melodDraftFlow.mockRejectedValue(Object.assign(new Error('AI provider not configured'), { status: 503 }));
    renderAt('/');
    send('@flow page the on-call on critical alerts');
    const run = await screen.findByTestId('pivt-draft-run');
    await waitFor(() => expect(run.getAttribute('data-status')).toBe('failed'));
    expect(within(run).getByText('AI provider not configured')).toBeTruthy();
  });

  test('Flows → Draft with pivt opens pivt with @flow focused, then drafts inline', async () => {
    renderAt('/automation/flows');
    fireEvent.click(await screen.findByRole('button', { name: 'Draft with pivt' }));
    await waitFor(() => expect(pivtInput().value).toBe('@flow '));
    await waitFor(() => expect(document.activeElement).toBe(pivtInput()));
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(localStorage.getItem('nano-pivt-open')).toBe('1');

    send('@flow Nightly hunt for svc_backup logins');
    await waitFor(() => expect(mock.melodDraftFlow).toHaveBeenCalledWith({ brief: 'Nightly hunt for svc_backup logins' }));
    await waitFor(() => expect(screen.getByTestId('where').textContent).toBe(`/automation/flows/${created.flow_id}`));
  });

  test('a bare @flow asks for the brief instead of drafting', async () => {
    renderAt('/');
    // Trailing space: the palette has closed, Enter sends the bare command.
    send('@flow ');
    await waitFor(() => expect(pivtInput().value).toBe('@flow '));
    expect(screen.queryByTestId('pivt-draft-run')).toBeNull();
    expect(mock.melodDraftFlow).not.toHaveBeenCalled();
  });

  test('@flow is registered and the canned suggestion label still maps to it', () => {
    expect(PIVT_COMMANDS.some((c) => c.keyword === '@flow' && c.accepts === 'text')).toBe(true);
    expect(suggestionToCommand('Draft an automation flow for this alert')).toBe('@flow');
  });

  test('hidden without melod:chat, without soar:manage, or without meloD', async () => {
    for (const setup of [
      () => mock.perms.delete('melod:chat'),
      () => mock.perms.delete('soar:manage'),
      () => (mock.melod = false),
    ]) {
      mock.melod = true;
      mock.perms = new Set(['soar:view', 'soar:run', 'soar:manage', 'melod:chat']);
      setup();
      renderAt('/automation/flows');
      expect(await screen.findByText('No flows yet')).toBeTruthy();
      expect(screen.queryByRole('button', { name: 'Draft with pivt' })).toBeNull();
      cleanup();
    }
  });
});
