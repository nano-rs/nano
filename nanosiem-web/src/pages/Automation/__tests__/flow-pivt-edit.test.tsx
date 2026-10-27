// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
//
// NAN-4653 — pivt edits the open SOAR flow conversationally, in its panel.
// Runs through the real pivt shell (PivtShellOverlay → PivtPanelBody →
// PivtInput → command router → edit-session runner) next to the real flow
// editor route:
//   - the open flow binds the composer ("Edit this flow with pivt…")
//   - a change request sends the page's CURRENT document, the version, the
//     conversation and the whole sentence
//   - the revision lands as ONE undo step with the changed step highlighted,
//     and nothing is saved, activated or run
//   - "now also …" continues the conversation
//   - off an editable flow, the same sentence stays chat / a new draft
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import type { Capabilities } from '@/hooks/use-capabilities';
import { PIVT_CHAT_MESSAGE_EVENT } from '@/enterprise/components/pivt/commands/router';
import { PivtShellOverlay } from '@/enterprise/components/pivt/PivtShellOverlay';
import { resetPivtDraftStore } from '@/enterprise/components/pivt/drafts/draft-store';
import { resetEditSessions } from '@/enterprise/components/pivt/drafts/edit-session';
import { resetEditableArtifact } from '@/contexts/EditableArtifactContext';
import { usePivtState } from '@/enterprise/hooks/use-pivt-state';
import { catalog, connection, flow, settings } from './fixtures';

const mock = vi.hoisted(() => ({
  perms: new Set(['soar:view', 'soar:run', 'soar:manage', 'melod:chat']),
  job: {
    value: null as unknown,
    fail: null as string | null,
    hold: false,
    release: null as null | (() => void),
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
  melodEditTurn: vi.fn(),
  melodDraftFlow: vi.fn(),
}));

function caps(): Capabilities {
  return {
    search: true, cases: false, notebooks: false, risk: false, melod: true, queryCorrection: false,
    customEnrichment: false, agentEnrichment: false, aiTuning: false, playbooks: false, incidents: false,
    siemHealth: true, sso: true, observabilityConvergence: false, iocLists: true, soar: true,
  };
}

vi.mock('@/lib/api', () => ({ api: { soar: mock.soarApi, melodEditTurn: mock.melodEditTurn, melodDraftFlow: mock.melodDraftFlow } }));
vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({ edition: 'enterprise', version: 'test', capabilities: caps() }),
}));
vi.mock('@/hooks/use-api', () => ({ useMelodStatus: () => ({ data: { connected: true } }) }));
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
vi.mock('@/enterprise/hooks/use-melod-job', () => ({
  pollMelodJob: async (fn: () => Promise<unknown>, opts?: { onProgress?: (m?: string) => void }) => {
    await fn();
    opts?.onProgress?.('Validating the revision');
    if (mock.job.hold) await new Promise<void>((r) => (mock.job.release = r));
    if (mock.job.fail) throw new Error(mock.job.fail);
    return mock.job.value;
  },
}));

import { AutomationFlowRoute } from '../index';

const FLOW = flow({ status: 'draft' });
const ADD = 'add a step that emails soc_oncall after containment';

function Shell() {
  const pivt = usePivtState();
  return (
    <PivtShellOverlay state={pivt}>
      <Routes>
        <Route path="/" element={<div>home</div>} />
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

const pivtInput = () => screen.getByLabelText('Message pivt') as HTMLTextAreaElement;
function send(text: string) {
  fireEvent.change(pivtInput(), { target: { value: text } });
  fireEvent.keyDown(pivtInput(), { key: 'Enter' });
}
const stepIds = () => screen.getAllByTestId('flow-step').map((b) => b.getAttribute('data-step-id'));

/** The server's revision: the open flow plus an approval-gated email step. */
function revision(base = FLOW) {
  const def = base.definition as { summary: string; description: string; value: { modules: unknown[] } };
  return {
    kind: 'flow',
    artifact_id: base.id,
    base_version: base.version,
    document: {
      name: base.name,
      trigger: base.trigger,
      definition: {
        ...def,
        value: {
          modules: [
            ...def.value.modules,
            { id: 'tell', summary: 'Email on-call', value: { type: 'notify.email', to: 'soc_oncall', subject: 'Contained', body: 'Host contained.', approval: 'required' } },
          ],
        },
      },
    },
    reply: 'Added an approval-gated email to soc_oncall after containment.',
    changed: ['tell'],
    facts: [{ label: 'Steps', value: '4' }, { label: 'Approvals', value: '2 gates' }],
    carried_findings: [],
    repaired: false,
  };
}

async function openFlow() {
  renderAt(`/automation/flows/${FLOW.id}`);
  await screen.findAllByTestId('flow-step');
  await waitFor(() => expect(pivtInput().placeholder).toBe('Edit this flow with pivt…'));
}

beforeEach(() => {
  localStorage.clear();
  localStorage.setItem('nano-pivt-open', '1');
  resetPivtDraftStore();
  resetEditSessions();
  resetEditableArtifact();
  mock.perms = new Set(['soar:view', 'soar:run', 'soar:manage', 'melod:chat']);
  mock.job.value = revision();
  mock.job.fail = null;
  mock.job.hold = false;
  mock.job.release = null;
  for (const fn of Object.values(mock.soarApi)) fn.mockReset();
  mock.melodEditTurn.mockReset();
  mock.melodEditTurn.mockResolvedValue({ job_id: 'j1', status: 'pending' });
  mock.melodDraftFlow.mockReset();
  mock.melodDraftFlow.mockResolvedValue({ job_id: 'j2', status: 'pending' });
  mock.soarApi.getSettings.mockResolvedValue(settings(true));
  mock.soarApi.getCatalog.mockResolvedValue(catalog());
  mock.soarApi.getConnections.mockResolvedValue({ connections: [connection()] });
  mock.soarApi.getRuns.mockResolvedValue({ runs: [], limit: 100, offset: 0 });
  mock.soarApi.getFlows.mockResolvedValue({ flows: [FLOW], event_overflow_count: 0, last_event_overflow_at: null, admission_backpressure: null });
  mock.soarApi.getFlowStats.mockResolvedValue({ flows: [] });
  mock.soarApi.getFlow.mockResolvedValue(FLOW);
});
afterEach(cleanup);

describe('pivt edits the open flow', () => {
  test('a turn sends the current document and lands as ONE undo step, highlighted, never saved', async () => {
    await openFlow();
    expect(stepIds()).not.toContain('tell');
    send(ADD);

    await waitFor(() => expect(mock.melodEditTurn).toHaveBeenCalledTimes(1));
    const request = mock.melodEditTurn.mock.calls[0][0];
    expect(request).toMatchObject({ kind: 'flow', artifact_id: FLOW.id, version: FLOW.version, conversation: [], instruction: ADD });
    expect(request.document.name).toBe(FLOW.name);
    expect(request.document.trigger).toMatchObject({ on: 'alert' });
    expect(request.document.definition.value.modules.map((m: { id: string }) => m.id)).toEqual(['lookup', 'gate', 'contain']);

    const run = await screen.findByTestId('pivt-draft-run');
    await waitFor(() => expect(run.getAttribute('data-status')).toBe('done'));
    expect(within(run).getByText(ADD)).toBeTruthy();
    expect(within(run).getByText(/Added an approval-gated email/)).toBeTruthy();
    expect(within(run).getByText('tell')).toBeTruthy();

    // On the page: the new step, highlighted, unsaved.
    await waitFor(() => expect(stepIds()).toContain('tell'));
    const tell = screen.getAllByTestId('flow-step').find((b) => b.getAttribute('data-step-id') === 'tell')!;
    expect(tell.getAttribute('data-pivt-changed')).toBe('true');
    expect(screen.getByText('unsaved')).toBeTruthy();

    // ONE undo step reverts the whole turn.
    fireEvent.click(screen.getByRole('button', { name: 'Undo' }));
    await waitFor(() => expect(stepIds()).not.toContain('tell'));
    expect(screen.queryByText('unsaved')).toBeNull();
    expect((screen.getByRole('button', { name: 'Undo' }) as HTMLButtonElement).disabled).toBe(true);

    // Never saved, activated or run; no modal.
    expect(mock.soarApi.updateFlow).not.toHaveBeenCalled();
    expect(mock.soarApi.queueFlow).not.toHaveBeenCalled();
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  test('"now also …" continues the conversation with the previous turn', async () => {
    await openFlow();
    send(ADD);
    await waitFor(() => expect(stepIds()).toContain('tell'));
    const second = revision();
    (second.document.definition.value.modules[3] as { summary: string }).summary = 'Email on-call (high only)';
    second.changed = ['tell'];
    second.reply = 'Limited the email to high severity.';
    mock.job.value = second;
    mock.melodEditTurn.mockClear();
    send('now also only email for high severity');
    await waitFor(() => expect(mock.melodEditTurn).toHaveBeenCalledTimes(1));
    const request = mock.melodEditTurn.mock.calls[0][0];
    expect(request.instruction).toBe('now also only email for high severity');
    expect(request.conversation).toEqual([
      { role: 'user', text: ADD },
      { role: 'pivt', text: 'Added an approval-gated email to soc_oncall after containment.' },
    ]);
    // The second turn starts from the page's current (unsaved) document.
    expect(request.document.definition.value.modules.map((m: { id: string }) => m.id)).toContain('tell');
    // A plain follow-up without an edit verb continues it too.
    mock.melodEditTurn.mockClear();
    send('the subject should mention the hostname');
    await waitFor(() => expect(mock.melodEditTurn).toHaveBeenCalledTimes(1));
  });

  test('progress streams into the run; edits made while pivt works win', async () => {
    mock.job.hold = true;
    await openFlow();
    send(ADD);
    const run = await screen.findByTestId('pivt-draft-run');
    expect(await within(run).findAllByText('Validating the revision')).not.toHaveLength(0);
    // The analyst deletes a step while the job runs.
    fireEvent.click(screen.getAllByTestId('flow-step').find((b) => b.getAttribute('data-step-id') === 'lookup')!);
    fireEvent.click(await screen.findByRole('button', { name: 'Delete step' }));
    await waitFor(() => expect(stepIds()).not.toContain('lookup'));
    act(() => mock.job.release?.());
    await waitFor(() => expect(run.getAttribute('data-status')).toBe('failed'));
    expect(within(run).getByText(/changed while pivt was working/)).toBeTruthy();
    expect(stepIds()).not.toContain('tell');
    expect(stepIds()).not.toContain('lookup');
  });

  test('a failed turn changes nothing on the page', async () => {
    mock.job.fail = 'pivt could not produce a valid revision after one repair attempt: module `tell`: notify.email must set "approval": "required"';
    await openFlow();
    send(ADD);
    const run = await screen.findByTestId('pivt-draft-run');
    await waitFor(() => expect(run.getAttribute('data-status')).toBe('failed'));
    expect(within(run).getByText('pivt could not make that change.')).toBeTruthy();
    expect(stepIds()).not.toContain('tell');
    expect(screen.queryByText('unsaved')).toBeNull();
  });
});

describe('edit intent routing', () => {
  test('on the open flow, "create a flow …" still drafts a NEW flow', async () => {
    mock.job.value = { flow_id: 'f9', name: 'n', version: 1, status: 'draft', trigger: { on: 'manual' }, module_count: 1, approval_gates: 0, repaired: false };
    await openFlow();
    send('create a flow that pages on-call for critical alerts');
    await waitFor(() => expect(mock.melodDraftFlow).toHaveBeenCalled());
    expect(mock.melodEditTurn).not.toHaveBeenCalled();
  });

  test('questions about the open flow stay chat', async () => {
    const chat = vi.fn();
    const onChat = (e: Event) => chat((e as CustomEvent<{ text: string }>).detail.text);
    window.addEventListener(PIVT_CHAT_MESSAGE_EVENT, onChat);
    try {
      await openFlow();
      send('why does this flow wait for approval?');
      await waitFor(() => expect(chat).toHaveBeenCalledWith('why does this flow wait for approval?'));
      expect(mock.melodEditTurn).not.toHaveBeenCalled();
    } finally {
      window.removeEventListener(PIVT_CHAT_MESSAGE_EVENT, onChat);
    }
  });

  test.each([
    ['nothing open', '/', () => {}],
    ['archived flow', `/automation/flows/${FLOW.id}`, () => mock.soarApi.getFlow.mockResolvedValue(flow({ status: 'archived' }))],
    ['no melod:chat', `/automation/flows/${FLOW.id}`, () => mock.perms.delete('melod:chat')],
    ['no soar:manage', `/automation/flows/${FLOW.id}`, () => mock.perms.delete('soar:manage')],
  ])('%s: an edit request is chat, and the composer is not bound', async (_label, path, setup) => {
    setup();
    const chat = vi.fn();
    const onChat = (e: Event) => chat((e as CustomEvent<{ text: string }>).detail.text);
    window.addEventListener(PIVT_CHAT_MESSAGE_EVENT, onChat);
    try {
      renderAt(path);
      if (path !== '/') await screen.findAllByTestId('flow-step');
      expect(pivtInput().placeholder).not.toContain('Edit this flow');
      send(ADD);
      await waitFor(() => expect(chat).toHaveBeenCalledWith(ADD));
      expect(mock.melodEditTurn).not.toHaveBeenCalled();
    } finally {
      window.removeEventListener(PIVT_CHAT_MESSAGE_EVENT, onChat);
    }
  });
});
