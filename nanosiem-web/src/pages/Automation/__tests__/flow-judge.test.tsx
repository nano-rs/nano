// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
//
// NAN-4660 — AI judge steps in the flow editor: palette add/drag, the
// inspector form, the canvas card, evidence scope and the meloD gate. Real
// api client; only fetch is replaced by an in-memory server.
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import type { Capabilities } from '@/hooks/use-capabilities';
import { setAccessToken } from '@/lib/auth-token';
import { catalog, connection, flow, settings } from './fixtures';
import { JUDGE_KEYS, judgeErrors } from '../judge-rules';

const env = vi.hoisted(() => ({
  perms: new Set<string>(),
  melod: true,
}));
vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({
    edition: 'enterprise',
    version: 'test',
    capabilities: {
      search: true, cases: false, notebooks: false, risk: false, melod: env.melod, queryCorrection: false, customEnrichment: false,
      agentEnrichment: false, aiTuning: false, playbooks: false, incidents: false, siemHealth: true, sso: true,
      observabilityConvergence: false, iocLists: true, soar: true,
    } satisfies Capabilities,
  }),
}));
vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({
    hasPermission: (p: string) => env.perms.has(p),
    hasAnyPermission: (ps: string[]) => ps.some((p) => env.perms.has(p)),
    isDemoUser: false,
    user: { id: 'me' },
  }),
}));

import { AutomationFlowRoute } from '../index';

const FLOW_ID = 'f0000000-0000-4000-8000-000000000001';
const CONN = 'c0000000-0000-4000-8000-000000000001';
type Mod = { id: string; summary?: string; value: Record<string, unknown> };
const lookup: Mod = { id: 'lookup', summary: 'Look up', value: { type: 'action', pack: 'crowdstrike', action: 'get_host', connection: CONN, input_transforms: { hostname: { type: 'expr', expr: 'flow_input.host' } }, approval: 'default' } };
const gate: Mod = { id: 'gate', value: { type: 'approval', prompt: 'Contain this host?', options: ['contain', 'skip'] } };

let modules: Mod[] = [];
let trigger: { on: string; match?: string | null } = { on: 'alert', match: null };
let calls: Array<{ method: string; path: string; body: unknown }> = [];

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}
async function fakeServer(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url, 'http://localhost');
  const method = (init?.method ?? 'GET').toUpperCase();
  const body = typeof init?.body === 'string' ? JSON.parse(init.body) : undefined;
  calls.push({ method, path: url.pathname, body });
  const p = url.pathname;
  if (p === '/api/soar/settings') return json(settings(true));
  if (p === '/api/soar/packs') return json(catalog());
  if (p === '/api/soar/connections') return json({ connections: [connection()] });
  if (p === '/api/soar/runs') return json({ runs: [], limit: 100, offset: 0 });
  if (p === '/api/soar/flows/validate') return json({ valid: true, module_count: modules.length, summary: 'valid' });
  if (p === `/api/soar/flows/${FLOW_ID}` && method === 'GET') return json(flow({ status: 'draft', trigger, definition: { summary: 'Contain', description: '', value: { modules } } }));
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
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const order = () => screen.getAllByTestId('flow-step').map((b) => b.getAttribute('data-step-id'));
const block = (id: string) => screen.getAllByTestId('flow-step').find((b) => b.getAttribute('data-step-id') === id)!;
const inspector = () => screen.getByTestId('flow-inspector');
const judgeRow = () => within(screen.getByTestId('flow-palette')).getByRole('button', { name: /Judge/ });
function dataTransfer() {
  const store: Record<string, string> = {};
  return { setData: (k: string, v: string) => { store[k] = v; }, getData: (k: string) => store[k], dropEffect: 'none', effectAllowed: 'all', types: [] };
}
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
async function openPalette() {
  fireEvent.click(screen.getByRole('button', { name: 'Blocks' }));
  return screen.getByTestId('flow-palette');
}
/** Paths the evidence picker offers right now. */
function evidenceOptions(): string[] {
  fireEvent.click(within(inspector()).getByRole('button', { name: 'Add evidence' }));
  const list = screen.getByRole('listbox', { name: 'Add evidence options' });
  const paths = within(list).getAllByRole('option').map((o) => o.querySelector('.font-mono')?.textContent ?? '');
  fireEvent.keyDown(list, { key: 'Escape' });
  return paths;
}

beforeEach(() => {
  calls = [];
  modules = [lookup, gate];
  trigger = { on: 'alert', match: null };
  env.perms = new Set(['soar:view', 'soar:run', 'soar:manage', 'melod:summarize']);
  env.melod = true;
  setAccessToken('test-bearer', 3600);
  vi.stubGlobal('fetch', vi.fn(fakeServer));
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('Judge block', () => {
  test('palette: Judge sits in Logic with an AI tag; click adds it with the server defaults', async () => {
    renderEditor();
    await ready();
    const palette = await openPalette();
    const row = judgeRow();
    expect((row as HTMLButtonElement).disabled).toBe(false);
    expect(row.getAttribute('draggable')).toBe('true');
    expect(within(row).getByText('AI').className).toMatch(/text-ai/);
    // Same group as Condition.
    const logic = within(palette).getByRole('button', { name: /Condition/ }).parentElement!;
    expect(logic.contains(row)).toBe(true);

    fireEvent.click(row);
    expect(order()).toEqual(['trigger', 'lookup', 'gate', 's1']);
    expect(within(block('s1')).getByText('JUDGE').className).toMatch(/text-ai/);
    expect(within(inspector()).getByText('Step s1 · AI judge')).toBeTruthy();
    // Defaults show as chips; the empty question and evidence are flagged inline.
    const labels = within(inspector()).getByTestId('judge-labels');
    expect(within(labels).getByText('yes')).toBeTruthy();
    expect(within(labels).getByText('no')).toBeTruthy();
    expect(within(inspector()).getByText('Question is required.')).toBeTruthy();
    expect(within(inspector()).getByText('Pick at least one evidence field.')).toBeTruthy();
    expect((within(inspector()).getByLabelText('Token cap') as HTMLInputElement).value).toBe('2000');
    expect(within(block('s1')).getByTestId('step-error').textContent).toBe('Question is required');
  });

  test('palette: drag drops the judge at the gap', async () => {
    renderEditor();
    await ready();
    await openPalette();
    await dragTo(judgeRow(), 'root:modules:gate');
    expect(order()).toEqual(['trigger', 'lookup', 's1', 'gate']);
  });

  test('inspector edits produce a module the server judge validator accepts; the card shows question and labels', async () => {
    renderEditor();
    await ready();
    await openPalette();
    fireEvent.click(judgeRow());
    const ins = inspector();

    fireEvent.change(within(ins).getByLabelText('Question'), { target: { value: 'Does this evidence support malicious activity on the host?' } });
    // Labels: invalid and duplicate drafts are refused inline; valid ones add as chips.
    const draft = within(ins).getByLabelText('New label');
    fireEvent.change(draft, { target: { value: 'unknown' } });
    expect(within(ins).getByText(/"unknown" is reserved/)).toBeTruthy();
    expect((within(ins).getByRole('button', { name: 'Add' }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(draft, { target: { value: 'YES' } });
    expect(within(ins).getByText('"YES" is already a label.')).toBeTruthy();
    fireEvent.change(draft, { target: { value: 'needs review' } });
    expect(within(ins).getByText('Use letters, digits, _ or - only.')).toBeTruthy();
    fireEvent.change(draft, { target: { value: 'needs_review' } });
    fireEvent.keyDown(draft, { key: 'Enter' });
    fireEvent.click(within(ins).getByRole('button', { name: 'Remove label yes' }));
    fireEvent.change(draft, { target: { value: 'malicious' } });
    fireEvent.click(within(ins).getByRole('button', { name: 'Add' }));
    // Two labels left after removing one more → remove is disabled at the floor.
    fireEvent.click(within(ins).getByRole('button', { name: 'Remove label no' }));
    expect((within(ins).getByRole('button', { name: 'Remove label malicious' }) as HTMLButtonElement).disabled).toBe(true);

    // Evidence from the trigger and an earlier step.
    fireEvent.click(within(ins).getByRole('button', { name: 'Add evidence' }));
    fireEvent.click(screen.getByRole('option', { name: /flow_input\.alert\.severity/ }));
    fireEvent.click(within(ins).getByRole('button', { name: 'Add evidence' }));
    fireEvent.click(screen.getByRole('option', { name: /results\.lookup/ }));
    expect(within(ins).getAllByTestId('judge-evidence-row')).toHaveLength(2);

    fireEvent.change(within(ins).getByLabelText('Token cap'), { target: { value: '9000' } });
    expect(within(ins).getByText('Whole number from 1 to 8000.')).toBeTruthy();
    fireEvent.change(within(ins).getByLabelText('Token cap'), { target: { value: '1500' } });

    // Card: question as title, labels as the sub-line, no errors.
    expect(within(block('s1')).getByText('Does this evidence support malicious activity on the host?')).toBeTruthy();
    expect(within(block('s1')).getByText('needs_review / malicious')).toBeTruthy();
    expect(within(block('s1')).queryByTestId('step-error')).toBeNull();

    fireEvent.click(screen.getByRole('button', { name: 'Save draft' }));
    await waitFor(() => expect(calls.some((c) => c.method === 'PUT')).toBe(true));
    const put = calls.find((c) => c.method === 'PUT')!.body as { definition: { value: { modules: Mod[] } } };
    const judge = put.definition.value.modules.find((m) => m.id === 's1')!;
    expect(judge.value).toEqual({
      type: 'judge',
      question: 'Does this evidence support malicious activity on the host?',
      labels: ['needs_review', 'malicious'],
      evidence: ['flow_input.alert.severity', expect.stringMatching(/^results\.lookup(\.|$)/)],
      token_cap: 1500,
      cache_ttl: '6h',
    });
    // Server shape: only ModuleValue::Judge keys (deny_unknown_fields), and every bound holds.
    expect(Object.keys(judge.value).every((k) => (JUDGE_KEYS as readonly string[]).includes(k))).toBe(true);
    expect(judgeErrors(judge.value)).toEqual([]);
  });

  test('evidence scope: no alert.* under a manual trigger, earlier steps only', async () => {
    trigger = { on: 'manual', match: null };
    modules = [lookup, { id: 'j', value: { type: 'judge', question: 'Bad?', labels: ['yes', 'no'], evidence: ['alert.severity'], token_cap: 2000, cache_ttl: '6h' } }, gate];
    renderEditor();
    await ready();
    fireEvent.click(block('j'));
    // A stored alert reference is flagged on the row and on the card.
    expect(within(inspector()).getByText(/A manual trigger has no alert/)).toBeTruthy();
    expect(within(block('j')).getByTestId('step-error').textContent).toMatch(/alert\.severity: a manual trigger has no alert/);
    const opts = evidenceOptions();
    expect(opts.filter((p) => p.startsWith('flow_input.alert.'))).toEqual([]);
    expect(opts.some((p) => p.startsWith('results.lookup'))).toBe(true);
    expect(opts.some((p) => p.startsWith('results.gate'))).toBe(false);
    expect(opts).toContain('run.id');
  });

  test('evidence scope: alert fields are offered under an alert trigger', async () => {
    modules = [lookup, { id: 'j', value: { type: 'judge', question: 'Bad?', labels: ['yes', 'no'], evidence: ['alert.severity'], token_cap: 2000, cache_ttl: '6h' } }];
    renderEditor();
    await ready();
    fireEvent.click(block('j'));
    expect(within(block('j')).queryByTestId('step-error')).toBeNull();
    // Already chosen (via the alert.* alias) is not offered again.
    const opts = evidenceOptions();
    expect(opts).toContain('flow_input.alert.entities.host');
    expect(opts).not.toContain('flow_input.alert.severity');
  });

  test('the condition picker offers the judge verdict with its labels', async () => {
    modules = [lookup, { id: 'j', value: { type: 'judge', question: 'Bad?', labels: ['malicious', 'benign'], evidence: ['alert.severity'], token_cap: 2000, cache_ttl: '6h' } }];
    renderEditor();
    await ready();
    await openPalette();
    fireEvent.click(within(screen.getByTestId('flow-palette')).getByRole('button', { name: /Condition/ }));
    fireEvent.click(within(inspector()).getAllByRole('button').find((b) => /choose a field/.test(b.textContent ?? ''))!);
    expect(screen.getByRole('option', { name: /results\.j\.verdict/ })).toBeTruthy();
  });

  test('gate: without melod:summarize the Judge row is disabled with the reason', async () => {
    env.perms.delete('melod:summarize');
    renderEditor();
    await ready();
    await openPalette();
    const row = judgeRow() as HTMLButtonElement;
    expect(row.disabled).toBe(true);
    expect(row.title).toBe('AI judge needs the melod:summarize permission');
    expect(row.getAttribute('draggable')).toBeNull();
  });

  test('gate: without meloD the Judge row is disabled with the reason', async () => {
    env.melod = false;
    renderEditor();
    await ready();
    await openPalette();
    expect((judgeRow() as HTMLButtonElement).title).toBe('AI judge needs meloD, which is not enabled for this tenant');
  });
});
