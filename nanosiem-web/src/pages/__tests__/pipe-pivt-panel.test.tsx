// @vitest-environment jsdom
//
// NAN-4609 — pivt works on Pipe steps in its panel (B3 of the panel-first
// inventory; the PipePivtWizard sheet is gone). Through the real pivt shell
// (PivtShellOverlay → panel → run card) next to the real Pipelines page and
// PipelineEditor (only the data workspace hook is faked):
//   - `@pipe <request>` sends the selected step, the steps before it, the
//     samples and the preview error to the parser-edit agent as a panel run
//   - a proposal is a diff card; Apply writes the draft (unsaved) through the
//     page bridge, a stale proposal is refused, Reject changes nothing
//   - a follow-up continues the meloD session on the same step
//   - drafting inserts a new step; read-only viewers get no Apply
//   - the editor's pivt button and the Here card start from the panel
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { useState } from 'react';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import type { Capabilities } from '@/hooks/use-capabilities';
import type { MelodEditParserResponse } from '@/lib/api';
import type { PipelineDraft, PipelinePreview, PipelineSample } from '@/lib/pipeline-types';

const mock = vi.hoisted(() => ({
  melod: true,
  perms: new Set<string>(),
  canEdit: true,
  melodEditParser: vi.fn(),
  jobResults: [] as unknown[],
  /** Latest draft the page holds (what Save draft would write). */
  draft: null as PipelineDraft | null,
  setDraft: null as ((d: PipelineDraft) => void) | null,
}));

function caps(): Capabilities {
  return {
    search: true, cases: false, notebooks: false, risk: false, melod: mock.melod, queryCorrection: false,
    customEnrichment: false, agentEnrichment: false, aiTuning: false, playbooks: false, incidents: false,
    siemHealth: true, sso: true, observabilityConvergence: false, iocLists: true, soar: false,
  };
}

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

vi.mock('@/lib/api', async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  api: autoApi({ melodEditParser: mock.melodEditParser }),
}));
vi.mock('@/hooks/use-api', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  const idle = () => ({ data: undefined, loading: false, isLoading: false, error: null, refetch: vi.fn(), mutate: vi.fn() });
  const stubs: Record<string, unknown> = {};
  for (const key of Object.keys(actual)) {
    stubs[key] = typeof actual[key] === 'function' && key.startsWith('use') ? idle : actual[key];
  }
  return { ...stubs, useMelodStatus: () => ({ data: { connected: true } }) };
});
vi.mock('@/hooks/use-capabilities', async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  useCapabilities: () => ({ edition: 'enterprise', version: 'test', capabilities: caps() }),
}));
vi.mock('@/hooks/use-shared-tenant', () => ({ useSharedTenant: () => true }));
vi.mock('@/enterprise/components/pivt/PivtCloseDialog', () => ({ PivtCloseDialog: () => null }));
vi.mock('@/components/threat-intel/use-threat-intel', () => ({ useEnrichEnabled: () => false }));
vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({
    hasPermission: (p: string) => mock.perms.has(p),
    hasAnyPermission: (ps: string[]) => ps.some((p) => mock.perms.has(p)),
    isDemoUser: false,
    user: { id: 'me', name: 'Dan Lussier', deployment_mode: 'enterprise_shared' },
    tenantRuntime: { key: 't1' },
  }),
}));
vi.mock('@/enterprise/hooks/use-melod-job', () => ({
  pollMelodJob: async (fn: () => Promise<unknown>) => {
    await fn();
    const next = mock.jobResults.shift();
    if (next instanceof Error) throw next;
    return next;
  },
  useMelodJob: () => ({ start: vi.fn(), result: null, error: null, loading: false, progress: null, reset: vi.fn() }),
}));

const INITIAL: PipelineDraft = {
  name: 'Firewall',
  description: '',
  revision: 4,
  steps: [
    { id: 'p', name: 'Parse JSON', kind: 'parse', enabled: true, config: { format: 'json', field: 'message' } },
    { id: 'v', name: 'Tag severity', kind: 'vrl', enabled: true, config: { code: '.severity = upcase(.sev)' } },
  ],
};
const SAMPLE: PipelineSample = {
  id: 'smp', name: 'fw-sample', source: 'pasted',
  events: [{ id: 'e1', input: { message: '{"sev":"high","src":"10.0.0.8"}' } }],
} as PipelineSample;
const PREVIEW: PipelinePreview = {
  revision: 4, fingerprint: 'f', inputCount: 1, outputCount: 0, stale: false,
  events: [{ inputId: 'e1', input: {}, outputs: [], outcome: 'error', trace: [{ stepId: 'v', outputs: [], error: 'function call error: upcase: expected string, got null' }] }],
};

// The real page and editor; only the data hook (API + caches) is faked.
vi.mock('@/hooks/use-pipeline-workspace', () => ({
  usePipelineWorkspace: () => {
    const [draft, setDraft] = useState<PipelineDraft>(INITIAL);
    mock.draft = draft;
    mock.setDraft = setDraft;
    const noop = () => {};
    return {
      loading: false, loadError: null, retry: noop,
      pipeline: { id: 's1', name: 'Firewall', description: '', sourceId: 's1', sourceName: 'fw-edge', sourceType: 'syslog', activeRevision: 3, draftRevision: 4, hasDraft: true, health: 'healthy', latestRelease: null },
      draft,
      changeDraft: setDraft,
      capabilities: { supportedSteps: ['vrl', 'parse'], capture: { available: false }, preview: true, ai: false },
      permissions: { view: true, edit: mock.canEdit, capture: false, release: false },
      dirty: draft !== INITIAL, busy: null, errors: {}, conflict: null, capabilitiesError: null,
      previewError: null, validation: null, capture: null, samples: [SAMPLE], frozen: SAMPLE, preview: PREVIEW,
      previewPending: false, canSaveCaptureSample: false, sampleNotice: null,
      laneInputs: [], routedInputs: [], previewInput: null, setPreviewInput: noop, inputs: undefined,
      save: noop, validate: noop, review: noop, startCapture: noop, stopCapture: noop, freeze: noop, selectSample: noop,
      runPreview: noop, saveSample: noop, loadRecentEvents: noop, pasteSample: noop, reloadLatest: noop, keepLocalEdits: noop,
      discardDraft: noop, retryCapabilities: noop, plan: null, planStale: false, closeReview: noop, publish: noop,
      releases: [], historyError: null, rollback: noop,
    };
  },
}));

import { BreadcrumbProvider } from '@/contexts/BreadcrumbContext';
import { PageContextProvider } from '@/contexts/PageContext';
import { PivtShellOverlay } from '@/enterprise/components/pivt/PivtShellOverlay';
import { resetPivtDraftStore } from '@/enterprise/components/pivt/drafts/draft-store';
import { resetRunActions } from '@/enterprise/components/pivt/drafts/interactive';
import { PIPE_NOT_OPEN_ERROR, resetPipeSessions } from '@/enterprise/components/pivt/drafts/pipe-run';
import { PIPE_VRL_STALE_ERROR } from '@/hooks/use-pipe-pivt-bridge';
import { usePivtState } from '@/enterprise/hooks/use-pivt-state';
import { Pipelines } from '../Pipelines';

let where = '';
function Where() {
  where = useLocation().pathname;
  return null;
}

function Shell() {
  const pivt = usePivtState();
  return (
    <PivtShellOverlay state={pivt}>
      <Where />
      <Routes>
        <Route path="/" element={<div>home</div>} />
        <Route path="/ingestion/pipelines" element={<div>inventory</div>} />
        <Route path="/ingestion/pipelines/:id" element={<Pipelines />} />
      </Routes>
    </PivtShellOverlay>
  );
}

function renderAt(path: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <PageContextProvider>
          <BreadcrumbProvider>
            <Shell />
          </BreadcrumbProvider>
        </PageContextProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const pivtInput = () => screen.getByLabelText('Message pivt') as HTMLTextAreaElement;
function send(text: string) {
  fireEvent.change(pivtInput(), { target: { value: text } });
  fireEvent.keyDown(pivtInput(), { key: 'Enter' });
}
async function settledRun(index = 0, status = 'done') {
  await waitFor(() => expect(screen.getAllByTestId('pivt-draft-run').length).toBeGreaterThan(index));
  const run = screen.getAllByTestId('pivt-draft-run')[index];
  await waitFor(() => expect(run.getAttribute('data-status')).toBe(status));
  return run;
}
/** The editor's pivt button (its wrapper carries the reason). */
const editorPivtButton = async () => {
  await screen.findAllByRole('button', { name: 'pivt' });
  return screen.getAllByRole('button', { name: 'pivt' }).find((b) => b.parentElement?.hasAttribute('title')) as HTMLButtonElement;
};
const cardTitled = (run: HTMLElement, title: RegExp) =>
  within(run).getAllByTestId('pivt-run-card').find((c) => title.test(c.textContent ?? ''))!;

const FIXED = '.severity = upcase(string(.sev) ?? "unknown")';
const FIX: MelodEditParserResponse = {
  session_id: 'sess-1',
  message: 'The sample has no `.sev` on some events, so `upcase` gets null. Coerce it first.',
  updated_vrl: FIXED,
  validation: { valid: true, errors: [] },
  test_results: [{ input: '{"sev":"high"}', success: true }],
};

/** Open the pipeline and select the "Tag severity" step in the editor. */
async function onTagStep() {
  renderAt('/ingestion/pipelines/s1');
  fireEvent.click((await screen.findAllByText('Tag severity'))[0]);
}

beforeEach(() => {
  localStorage.clear();
  localStorage.setItem('nano-pivt-open', '1');
  resetPivtDraftStore();
  resetRunActions();
  resetPipeSessions();
  mock.melod = true;
  mock.canEdit = true;
  mock.perms = new Set(['melod:parser', 'log_sources:view', 'log_sources:edit']);
  mock.jobResults = [];
  mock.melodEditParser.mockReset().mockResolvedValue({ job_id: 'j1', status: 'running' });
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

describe('@pipe works on the open pipeline in the pivt panel (NAN-4609)', () => {
  test('sends the selected step, the steps before it, the sample and the preview error; Apply writes the draft, unsaved', async () => {
    await onTagStep();
    mock.jobResults = [FIX];
    send('@pipe fix the preview error');

    await waitFor(() => expect(mock.melodEditParser).toHaveBeenCalledTimes(1));
    const req = mock.melodEditParser.mock.calls[0][0];
    expect(req).toMatchObject({ parser_id: 's1', current_vrl: '.severity = upcase(.sev)', sample_logs: ['{"sev":"high","src":"10.0.0.8"}'] });
    expect(req.session_id).toBeUndefined();
    expect(req.base_parser_vrl).toContain('parse_json');
    expect(req.message).toContain('upcase: expected string');
    expect(req.message).toContain('fix the preview error');

    const run = await settledRun();
    expect(within(run).getByText('fw-edge')).toBeTruthy();
    expect(within(run).getByText('step 2 · Tag severity')).toBeTruthy();
    expect(within(run).getByText(/gets null\. Coerce it first/)).toBeTruthy();
    const card = cardTitled(run, /Proposed VRL · step 2 · Tag severity/);
    expect(within(card).getByTestId('pivt-diff')).toBeTruthy();
    expect(within(card).getByText('1/1 ok')).toBeTruthy();
    // Nothing changes until Apply.
    expect(mock.draft).toBe(INITIAL);

    fireEvent.click(within(card).getByRole('button', { name: 'Apply to step' }));
    await waitFor(() => expect(card.getAttribute('data-state')).toBe('applied'));
    expect(within(card).getByText(/In the draft, unsaved/)).toBeTruthy();
    expect(mock.draft!.steps[1]).toMatchObject({ id: 'v', name: 'Tag severity', kind: 'vrl', config: { code: FIXED } });
    expect(where).toBe('/ingestion/pipelines/s1');
  });

  test('a follow-up continues the meloD session on the same step, now holding the applied VRL', async () => {
    await onTagStep();
    mock.jobResults = [FIX, { session_id: 'sess-1', message: 'Done: it also drops `.debug`.', updated_vrl: `${FIXED}\ndel(.debug)` }];
    send('@pipe fix the preview error');
    const first = await settledRun(0);
    fireEvent.click(within(cardTitled(first, /Proposed VRL/)).getByRole('button', { name: 'Apply to step' }));
    await waitFor(() => expect(mock.draft!.steps[1].config).toEqual({ code: FIXED }));

    const follow = cardTitled(first, /Ask a follow-up/);
    fireEvent.change(within(follow).getByLabelText('Follow-up for pivt'), { target: { value: 'also drop the debug field' } });
    fireEvent.click(within(follow).getByRole('button', { name: 'Ask' }));
    await waitFor(() => expect(mock.melodEditParser).toHaveBeenCalledTimes(2));
    expect(mock.melodEditParser.mock.calls[1][0]).toMatchObject({ session_id: 'sess-1', current_vrl: FIXED });
    const second = await settledRun(1);
    expect(within(second).getByText('also drop the debug field')).toBeTruthy();
    expect(cardTitled(second, /Proposed VRL · step 2 · Tag severity/)).toBeTruthy();
  });

  test('a proposal for a step the analyst changed since is refused; Reject changes nothing', async () => {
    await onTagStep();
    mock.jobResults = [FIX, FIX];
    send('@pipe fix the preview error');
    const run = await settledRun(0);
    const edited: PipelineDraft = {
      ...INITIAL,
      steps: [INITIAL.steps[0], { ...INITIAL.steps[1], config: { code: '.severity = "mine"' } }],
    };
    act(() => mock.setDraft!(edited));
    const card = cardTitled(run, /Proposed VRL/);
    fireEvent.click(within(card).getByRole('button', { name: 'Apply to step' }));
    await waitFor(() => expect(card.getAttribute('data-state')).toBe('failed'));
    expect(within(card).getByText(PIPE_VRL_STALE_ERROR)).toBeTruthy();
    expect(mock.draft).toBe(edited);

    send('@pipe fix the preview error');
    const again = await settledRun(1);
    const second = cardTitled(again, /Proposed VRL/);
    fireEvent.click(within(second).getByRole('button', { name: 'Reject' }));
    await waitFor(() => expect(second.getAttribute('data-state')).toBe('rejected'));
    expect(mock.draft).toBe(edited);
  });

  test('the Here card drafts a new step from the samples; Insert step adds it after the selected step', async () => {
    await onTagStep();
    mock.jobResults = [{ session_id: 's', message: 'A step that tags internal sources.', updated_vrl: '.internal = is_private_ip(.src) ?? false' }];
    fireEvent.click(await screen.findByRole('button', { name: 'Draft a pipeline step from the sample events' }));
    await waitFor(() => expect(mock.melodEditParser).toHaveBeenCalledTimes(1));
    // Draft mode: the agent edits a placeholder; both steps before it are the base.
    expect(mock.melodEditParser.mock.calls[0][0].current_vrl).toBe('.');
    expect(mock.melodEditParser.mock.calls[0][0].base_parser_vrl).toContain('upcase');
    const run = await settledRun();
    const card = cardTitled(run, /Proposed VRL · new step after Tag severity/);
    fireEvent.click(within(card).getByRole('button', { name: 'Insert step' }));
    await waitFor(() => expect(card.getAttribute('data-state')).toBe('applied'));
    expect(mock.draft!.steps.map((s) => s.name)).toEqual(['Parse JSON', 'Tag severity', 'pivt step']);
    expect(mock.draft!.steps[2].config).toEqual({ code: '.internal = is_private_ip(.src) ?? false' });
  });

  test('read-only viewers can ask but get no Apply', async () => {
    mock.canEdit = false;
    mock.perms.delete('log_sources:edit');
    await onTagStep();
    mock.jobResults = [FIX];
    send('@pipe fix the preview error');
    const card = cardTitled(await settledRun(), /Proposed VRL/);
    expect(within(card).queryByRole('button', { name: 'Apply to step' })).toBeNull();
    expect(within(card).getByText(/need permission to edit this pipeline/)).toBeTruthy();
  });

  test('the editor pivt button opens the panel with @pipe ready; no sheet opens', async () => {
    localStorage.setItem('nano-pivt-open', '0');
    renderAt('/ingestion/pipelines/s1');
    fireEvent.click(await editorPivtButton());
    await waitFor(() => expect(pivtInput().value).toBe('@pipe '));
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(mock.melodEditParser).not.toHaveBeenCalled();
  });

  test('without melod:parser the button is off and a typed @pipe fails in the panel with the reason', async () => {
    mock.perms.delete('melod:parser');
    renderAt('/ingestion/pipelines/s1');
    const button = await editorPivtButton();
    expect(button.disabled).toBe(true);
    expect(button.parentElement?.getAttribute('title')).toMatch(/melod:parser/);
    send('@pipe explain this step');
    const run = await settledRun(0, 'failed');
    expect(within(run).getByText(/requires the melod:parser permission/)).toBeTruthy();
    expect(mock.melodEditParser).not.toHaveBeenCalled();
  });

  test('off a pipeline: @pipe opens the inventory and the run says to open one', async () => {
    renderAt('/');
    send('@pipe fix the preview error');
    await waitFor(() => expect(where).toBe('/ingestion/pipelines'));
    const run = await settledRun(0, 'failed');
    expect(within(run).getByText(PIPE_NOT_OPEN_ERROR)).toBeTruthy();
  });

  test('a failed agent call stays in pivt with the reason; the draft is unchanged', async () => {
    await onTagStep();
    mock.jobResults = [new Error('The AI provider is not configured for this tenant')];
    send('@pipe fix the preview error');
    const run = await settledRun(0, 'failed');
    expect(within(run).getByText(/not configured for this tenant/)).toBeTruthy();
    expect(within(run).getByText(/The pipeline draft is unchanged/)).toBeTruthy();
    expect(mock.draft).toBe(INITIAL);
  });
});
