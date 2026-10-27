// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
//
// NAN-4546 — flow editor interactions through the REAL api client: only
// global fetch is replaced by an in-memory server, so request paths, methods
// and bodies are exactly what the browser would send.
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import type { Capabilities } from '@/hooks/use-capabilities';
import { setAccessToken } from '@/lib/auth-token';
import { catalog, connection, flow, settings } from './fixtures';

const auth = vi.hoisted(() => ({ perms: new Set(['soar:view', 'soar:run', 'soar:manage', 'soar:approve']) }));
vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({
    edition: 'enterprise',
    version: 'test',
    capabilities: {
      search: true, cases: false, notebooks: false, risk: false, melod: false, queryCorrection: false, customEnrichment: false,
      agentEnrichment: false, aiTuning: false, playbooks: false, incidents: false, siemHealth: true, sso: true,
      observabilityConvergence: false, iocLists: true, soar: true,
    } satisfies Capabilities,
  }),
}));
vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({
    hasPermission: (p: string) => auth.perms.has(p),
    hasAnyPermission: (ps: string[]) => ps.some((p) => auth.perms.has(p)),
    isDemoUser: false,
    user: { id: 'me' },
  }),
}));

import { AutomationFlowRoute } from '../index';

const FLOW_ID = 'f0000000-0000-4000-8000-000000000001';
const CONN = 'c0000000-0000-4000-8000-000000000001';
const definition = {
  summary: 'Contain',
  description: '',
  value: {
    modules: [
      { id: 'lookup', summary: 'Look up', value: { type: 'action', pack: 'crowdstrike', action: 'get_host', connection: CONN, input_transforms: { hostname: { type: 'expr', expr: 'flow_input.host' } }, approval: 'default' } },
      { id: 'gate', value: { type: 'approval', prompt: 'Contain this host?', options: ['contain', 'skip'] }, suspend: { required_events: 1, timeout_secs: 3600, resume_form: 'none' } },
      { id: 'contain', value: { type: 'action', pack: 'crowdstrike', action: 'contain_host', connection: CONN, input_transforms: { hostname: { type: 'expr', expr: 'flow_input.host' } }, approval: 'required' }, mock: { enabled: false, return_value: null } },
    ],
  },
};

interface Call { method: string; path: string; body: unknown; auth: string | null }
let calls: Call[] = [];
let validateResponse: { status: number; body: unknown } = { status: 200, body: { valid: true, module_count: 3, summary: 'valid' } };

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}
async function fakeServer(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url, 'http://localhost');
  const method = (init?.method ?? 'GET').toUpperCase();
  const body = typeof init?.body === 'string' ? JSON.parse(init.body) : undefined;
  calls.push({ method, path: url.pathname, body, auth: new Headers(init?.headers).get('Authorization') });
  const p = url.pathname;
  if (p === '/api/soar/settings') return json(settings(true));
  if (p === '/api/soar/packs') return json(catalog());
  if (p === '/api/soar/connections') return json({ connections: [connection()] });
  if (p === '/api/soar/runs') return json({ runs: [], limit: 100, offset: 0 });
  if (p === '/api/soar/flows/validate') return json(validateResponse.body, validateResponse.status);
  if (p === `/api/soar/flows/${FLOW_ID}` && method === 'GET') return json(flow({ status: 'draft', definition }));
  if (p === `/api/soar/flows/${FLOW_ID}` && method === 'PUT') return json(flow({ ...(body as object), version: 4 }));
  return json({ error: { code: 'NOT_FOUND', message: `unhandled ${method} ${p}` } }, 404);
}

function renderEditor() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[`/automation/flows/${FLOW_ID}`]}>
        <Routes>
          <Route path="/automation/flows/:id" element={<AutomationFlowRoute />} />
          <Route path="/automation/runs/:id" element={<div>run page</div>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const order = () => screen.getAllByTestId('flow-step').map((b) => b.getAttribute('data-step-id'));
const block = (id: string) => screen.getAllByTestId('flow-step').find((b) => b.getAttribute('data-step-id') === id)!;
function dataTransfer() {
  const store: Record<string, string> = {};
  return { setData: (k: string, v: string) => { store[k] = v; }, getData: (k: string) => store[k], dropEffect: 'none', effectAllowed: 'all', types: [] };
}
/** Native DnD as jsdom sees it: dragstart → (deferred state) → dragover → drop on a gap. */
async function dragTo(source: HTMLElement, gapKey: string) {
  const dt = dataTransfer();
  await act(async () => {
    fireEvent.dragStart(source, { dataTransfer: dt });
    await new Promise((r) => setTimeout(r, 0));
  });
  const gap = screen.getAllByTestId('drop-gap').find((g) => g.getAttribute('data-drop') === gapKey);
  expect(gap, `drop gap ${gapKey}`).toBeTruthy();
  fireEvent.dragOver(gap!, { dataTransfer: dt });
  fireEvent.drop(gap!, { dataTransfer: dt });
  fireEvent.dragEnd(source, { dataTransfer: dt });
}
async function ready() {
  await screen.findByTestId('flow-canvas');
  await waitFor(() => expect(within(block('lookup')).getByText('Get host details · CrowdStrike')).toBeTruthy());
}

beforeEach(() => {
  calls = [];
  validateResponse = { status: 200, body: { valid: true, module_count: 3, summary: 'valid' } };
  auth.perms = new Set(['soar:view', 'soar:run', 'soar:manage', 'soar:approve']);
  setAccessToken('test-bearer', 3600);
  vi.stubGlobal('fetch', vi.fn(fakeServer));
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('Flow editor', () => {
  test('insert from palette: click appends, drag drops at the gap', async () => {
    renderEditor();
    await ready();
    fireEvent.click(screen.getByRole('button', { name: 'Blocks' }));
    const palette = screen.getByTestId('flow-palette');
    fireEvent.click(within(palette).getByRole('button', { name: /Pass-through/ }));
    expect(order()).toEqual(['trigger', 'lookup', 'gate', 'contain', 's1']);
    expect(screen.getByText('unsaved')).toBeTruthy();

    // The palette stays open for the next block.
    await dragTo(within(screen.getByTestId('flow-palette')).getByRole('button', { name: /Loop/ }), 'root:modules:gate');
    expect(order()).toEqual(['trigger', 'lookup', 's2', 'gate', 'contain', 's1']);
    expect(screen.getByTestId('flow-loop')).toBeTruthy();
    // The new loop opens in the inspector with its own checks.
    expect(within(screen.getByTestId('flow-inspector')).getByText('Step s2 · bounded loop')).toBeTruthy();
  });

  test('drag Condition onto a root gap inserts the branch; a second one is refused', async () => {
    renderEditor();
    await ready();
    fireEvent.click(screen.getByRole('button', { name: 'Blocks' }));
    const condRow = () => within(screen.getByTestId('flow-palette')).getByRole('button', { name: /Condition/ });

    // While a Condition drags, only root gaps light up — never inside a lane.
    await act(async () => {
      fireEvent.dragStart(condRow(), { dataTransfer: dataTransfer() });
      await new Promise((r) => setTimeout(r, 0));
    });
    const gaps = screen.getAllByTestId('drop-gap').map((g) => g.getAttribute('data-drop'));
    expect(gaps).toEqual(['root:modules:lookup', 'root:modules:gate', 'root:modules:contain', 'root:modules:end']);
    expect(screen.getAllByText('drop here').length).toBe(4);
    fireEvent.dragEnd(condRow());

    await dragTo(condRow(), 'root:modules:end');
    expect(order()).toEqual(['trigger', 'lookup', 'gate', 'contain', 's1']);
    expect(screen.getByTestId('lane-then')).toBeTruthy();
    expect(screen.getByTestId('lane-else')).toBeTruthy();

    // One condition per flow: no gap accepts a second one.
    await act(async () => {
      fireEvent.dragStart(condRow(), { dataTransfer: dataTransfer() });
      await new Promise((r) => setTimeout(r, 0));
    });
    expect(screen.queryAllByTestId('drop-gap')).toHaveLength(0);
    fireEvent.dragEnd(condRow());
  });

  test('reorder by drag and by keyboard; approval policy travels with the step', async () => {
    renderEditor();
    await ready();
    await dragTo(block('contain'), 'root:modules:lookup');
    expect(order()).toEqual(['trigger', 'contain', 'lookup', 'gate']);
    expect(within(block('contain')).getByText(/always approved/)).toBeTruthy();
    fireEvent.keyDown(block('gate'), { key: 'ArrowUp', altKey: true });
    expect(order()).toEqual(['trigger', 'contain', 'gate', 'lookup']);
    // Inspector buttons do the same.
    fireEvent.click(block('lookup'));
    fireEvent.click(screen.getByRole('button', { name: 'Move up' }));
    expect(order()).toEqual(['trigger', 'contain', 'lookup', 'gate']);
  });

  test('inspector edit shows the error inline, undo restores it', async () => {
    renderEditor();
    await ready();
    fireEvent.click(block('lookup'));
    // NAN-4586: a bare path opens in the easy field picker; Advanced shows the raw text.
    expect(screen.getByLabelText('hostname field').getAttribute('title')).toBe('flow_input.host');
    fireEvent.click(screen.getByRole('button', { name: 'hostname advanced' }));
    const input = screen.getByLabelText('hostname expression') as HTMLInputElement;
    expect(input.value).toBe('flow_input.host');
    fireEvent.change(input, { target: { value: '' } });
    expect(within(block('lookup')).getByTestId('step-error').textContent).toBe('hostname is required');
    fireEvent.change(screen.getByLabelText('hostname expression'), { target: { value: 'flow_input.h' } });
    fireEvent.change(screen.getByLabelText('hostname expression'), { target: { value: 'flow_input.hostname' } });
    // Keystrokes in one field coalesce into one undo step.
    fireEvent.click(screen.getByRole('button', { name: 'Undo' }));
    expect((screen.getByLabelText('hostname expression') as HTMLInputElement).value).toBe('flow_input.host');
    expect(screen.queryByText('unsaved')).toBeNull();
    // Structural edits undo with Ctrl+Z.
    fireEvent.click(screen.getByRole('button', { name: 'Duplicate step' }));
    expect(order()).toEqual(['trigger', 'lookup', 'lookup1', 'gate', 'contain']);
    fireEvent.click(screen.getByRole('button', { name: 'Delete step' }));
    expect(order()).toEqual(['trigger', 'lookup', 'gate', 'contain']);
    fireEvent.keyDown(window, { key: 'z', ctrlKey: true });
    expect(order()).toEqual(['trigger', 'lookup', 'lookup1', 'gate', 'contain']);
  });

  test('validate: a server error naming a step lands on that step', async () => {
    validateResponse = { status: 400, body: { error: { code: 'INVALID', message: 'invalid flow definition: gate approval metadata exceeds profile' } } };
    renderEditor();
    await ready();
    fireEvent.click(screen.getByRole('button', { name: 'Validate' }));
    const findings = await screen.findByTestId('validation-findings');
    expect(within(findings).getByRole('button', { name: 'gate' })).toBeTruthy();
    expect(within(block('gate')).getByTestId('step-error').textContent).toMatch(/approval metadata exceeds profile/);
    const req = calls.find((c) => c.path === '/api/soar/flows/validate')!;
    expect(req.method).toBe('POST');
    expect((req.body as { definition: typeof definition }).definition.value.modules.map((m) => m.id)).toEqual(['lookup', 'gate', 'contain']);
    expect((screen.getByRole('button', { name: 'Activate' }) as HTMLButtonElement).disabled).toBe(true);
  });

  test('validate: sends the trigger and shows trigger-scope findings on their step (NAN-4651)', async () => {
    validateResponse = { status: 200, body: { valid: false, module_count: 3, summary: 'valid', findings: ['module `lookup`: alert.user.name: a manual trigger has no alert; use an alert trigger or a run input'] } };
    renderEditor();
    await ready();
    fireEvent.click(screen.getByRole('button', { name: 'Validate' }));
    const findings = await screen.findByTestId('validation-findings');
    expect(within(findings).getByRole('button', { name: 'lookup' })).toBeTruthy();
    expect(within(block('lookup')).getByTestId('step-error').textContent).toMatch(/a manual trigger has no alert/);
    const req = calls.find((c) => c.path === '/api/soar/flows/validate')!;
    expect((req.body as { trigger?: string }).trigger).toBe('alert');
    expect((screen.getByRole('button', { name: 'Activate' }) as HTMLButtonElement).disabled).toBe(true);
  });

  test('save: PUT carries the edited definition, the version and untouched fields', async () => {
    renderEditor();
    await ready();
    fireEvent.click(block('gate'));
    fireEvent.change(screen.getByLabelText('Message to approver'), { target: { value: 'Contain FIN-LT-0388?' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save draft' }));
    await waitFor(() => expect(calls.some((c) => c.method === 'PUT')).toBe(true));
    const put = calls.find((c) => c.method === 'PUT')!;
    expect(put.path).toBe(`/api/soar/flows/${FLOW_ID}`);
    expect(put.auth).toBe('Bearer test-bearer');
    const body = put.body as { expected_version: number; status: string; name: string; trigger: unknown; definition: typeof definition };
    expect(body.expected_version).toBe(3);
    expect(body.status).toBe('draft');
    expect(body.trigger).toEqual({ on: 'alert', match: 'severity >= high', cron: null });
    const mods = body.definition.value.modules as Array<Record<string, unknown> & { value: Record<string, unknown> }>;
    expect(mods[1].value.prompt).toBe('Contain FIN-LT-0388?');
    // Fields the editor never touches survive the round-trip.
    expect(mods[2].mock).toEqual({ enabled: false, return_value: null });
    expect(mods[2].value.approval).toBe('required');
    await waitFor(() => expect(screen.queryByText('unsaved')).toBeNull());
  });

  test('archived flows are read-only', async () => {
    vi.stubGlobal('fetch', vi.fn(async (i: RequestInfo | URL, init?: RequestInit) => {
      const r = await fakeServer(i, init);
      const u = new URL(typeof i === 'string' ? i : i instanceof URL ? i.href : i.url, 'http://localhost');
      if (u.pathname === `/api/soar/flows/${FLOW_ID}`) return json(flow({ status: 'archived', definition }));
      return r;
    }));
    renderEditor();
    await ready();
    expect(block('lookup').getAttribute('draggable')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Undo' })).toBeNull();
    expect(screen.getByRole('button', { name: 'Restore as draft' })).toBeTruthy();
  });
});

// NAN-4661: "add to <lane>" opens a picker (nothing guessed); a palette click
// inserts after the selected step, never implicitly into `then`.
describe('Flow editor: add-to picker and palette insertion point', () => {
  const lane = (l: string) => within(screen.getByTestId(`lane-${l}`)).queryAllByTestId('flow-step').map((b) => b.getAttribute('data-step-id'));
  const palette = () => screen.getByTestId('flow-palette');
  /** Opens the palette and adds a Condition with nothing selected: it lands at the root end. */
  async function withCondition() {
    renderEditor();
    await ready();
    fireEvent.click(screen.getByRole('button', { name: 'Blocks' }));
    fireEvent.click(within(palette()).getByRole('button', { name: /Condition/ }));
    expect(order()).toEqual(['trigger', 'lookup', 'gate', 'contain', 's1']);
    expect(lane('then')).toEqual([]);
  }
  async function pick(laneButton: RegExp, query: string, option: RegExp) {
    fireEvent.click(screen.getByRole('button', { name: laneButton }));
    const picker = await screen.findByTestId('block-picker');
    const search = within(picker).getByLabelText('Search blocks to add');
    fireEvent.change(search, { target: { value: query } });
    expect(within(picker).getByRole('option', { name: option }).getAttribute('aria-selected')).toBe('true');
    fireEvent.keyDown(search, { key: 'Enter' });
    await waitFor(() => expect(screen.queryByTestId('block-picker')).toBeNull());
  }

  test('add to else: the picked block lands in the else lane', async () => {
    await withCondition();
    await pick(/add to else/, 'email', /^Email/);
    expect(lane('else')).toEqual(['s2']);
    expect(lane('then')).toEqual([]);
    expect(within(block('s2')).getByText(/EMAIL/)).toBeTruthy();
  });

  test('add to then inserts nothing until a pick; Esc closes; entries match the palette', async () => {
    await withCondition();
    fireEvent.click(screen.getByRole('button', { name: /add to then/ }));
    const picker = await screen.findByTestId('block-picker');
    expect(order()).toEqual(['trigger', 'lookup', 'gate', 'contain', 's1']);
    // Same entries as the palette; a lane refuses a second condition, and Judge carries its reason.
    expect(within(picker).getByRole('option', { name: /^Condition/ }).hasAttribute('disabled')).toBe(true);
    const judge = within(picker).getByRole('option', { name: /^Judge/ });
    expect(judge.hasAttribute('disabled')).toBe(true);
    expect(judge.getAttribute('title')).toBeTruthy();
    expect(within(picker).getByRole('option', { name: /crowdstrike\.get_host/ })).toBeTruthy();
    // Arrow keys move over enabled rows only.
    const search = within(picker).getByLabelText('Search blocks to add');
    expect(within(picker).getByRole('option', { name: /^Loop/ }).getAttribute('aria-selected')).toBe('true');
    fireEvent.keyDown(search, { key: 'ArrowDown' });
    expect(within(picker).getByRole('option', { name: /^Approval gate/ }).getAttribute('aria-selected')).toBe('true');
    fireEvent.keyDown(search, { key: 'Escape' });
    await waitFor(() => expect(screen.queryByTestId('block-picker')).toBeNull());
    expect(order()).toEqual(['trigger', 'lookup', 'gate', 'contain', 's1']);
    expect(screen.queryByText(/PASS/)).toBeNull();
    // The window Escape handler did not also close the palette.
    expect(screen.getByTestId('flow-palette')).toBeTruthy();
  });

  test('palette click with a step selected inside else inserts right after it', async () => {
    await withCondition();
    await pick(/add to else/, 'email', /^Email/);
    await pick(/add to else/, 'search', /^nPL search/);
    expect(lane('else')).toEqual(['s2', 's3']);
    // Select s2 on the canvas (closes the palette), then reopen the palette.
    fireEvent.click(block('s2'));
    fireEvent.click(screen.getByRole('button', { name: 'Blocks' }));
    fireEvent.click(within(palette()).getByRole('button', { name: /Pass-through/ }));
    expect(lane('else')).toEqual(['s2', 's4', 's3']);
    expect(lane('then')).toEqual([]);
  });

  test('palette click with nothing selected and a condition present appends to root, not then', async () => {
    await withCondition();
    // Close the inspector: nothing selected.
    fireEvent.click(screen.getByRole('button', { name: 'Close' }));
    fireEvent.click(within(palette()).getByRole('button', { name: /Pass-through/ }));
    expect(lane('then')).toEqual([]);
    expect(lane('else')).toEqual([]);
    expect(order()).toEqual(['trigger', 'lookup', 'gate', 'contain', 's1', 's2']);
  });

  test('palette click after an add-to pick follows the selected new step in that lane', async () => {
    await withCondition();
    await pick(/add to else/, 'email', /^Email/);
    fireEvent.click(within(palette()).getByRole('button', { name: /Pass-through/ }));
    expect(lane('else')).toEqual(['s2', 's3']);
  });
});
