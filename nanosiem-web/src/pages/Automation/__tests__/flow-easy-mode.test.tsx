// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
//
// NAN-4586 — easy mode through the real flow editor and run dialog. Only
// global fetch is replaced, so request bodies are exactly what ships.
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import type { Capabilities } from '@/hooks/use-capabilities';
import type { SoarFlow } from '@/lib/api/soar';
import { setAccessToken } from '@/lib/auth-token';
import { EditorView } from '@codemirror/view';
import { deleteCharBackward } from '@codemirror/commands';
import { catalog, connection, flow, settings } from './fixtures';

vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({
    edition: 'enterprise',
    version: 'test',
    capabilities: {
      search: true, cases: true, notebooks: false, risk: false, melod: false, queryCorrection: false, customEnrichment: false,
      agentEnrichment: false, aiTuning: false, playbooks: false, incidents: false, siemHealth: true, sso: true,
      observabilityConvergence: false, iocLists: true, soar: true,
    } satisfies Capabilities,
  }),
}));
const perms = vi.hoisted(() => ({ denied: new Set<string>() }));
vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({
    hasPermission: (p: string) => !perms.denied.has(p),
    hasAnyPermission: () => true,
    isDemoUser: false,
    user: { id: 'me' },
  }),
}));

import { AutomationFlowRoute } from '../index';

const FLOW_ID = 'f0000000-0000-4000-8000-000000000001';
const CONN = 'c0000000-0000-4000-8000-000000000001';
const ALERT_ID = 'a0000000-0000-4000-8000-000000000001';
const CASE_ID = 'c5000000-0000-4000-8000-000000000042';
const definition = () => ({
  summary: 'Contain',
  description: '',
  value: {
    modules: [
      { id: 'spread', summary: 'Spread', value: { type: 'search', query: 'process_name=powershell.exe', window: '24h', limit: 100 } },
      { id: 'lookup', summary: 'Look up', value: { type: 'action', pack: 'crowdstrike', action: 'get_host', connection: CONN, input_transforms: { hostname: { type: 'expr', expr: '' } }, approval: 'default' } },
      {
        id: 'route',
        value: {
          type: 'branchone',
          branches: [{ expr: 'flow_input.alert.severity in [high, critical]', summary: 'then', modules: [{ id: 'note', value: { type: 'identity' } }] }],
          default: [],
        },
      },
    ],
  },
});

interface Call { method: string; path: string; query: string; body: unknown }
let calls: Call[] = [];
let current: SoarFlow;
let validateRule: { valid: boolean; errors: string[] } = { valid: true, errors: [] };
/** POST /api/soar/flows/validate-search answer (NAN-4585 `SearchValidation`); null = endpoint absent (404). */
let validateSearch: { valid: boolean; errors: Array<{ field: string; message: string; start: number | null; end: number | null; line: number | null; column: number | null }> } | null = { valid: true, errors: [] };

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}
async function fakeServer(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url, 'http://localhost');
  const method = (init?.method ?? 'GET').toUpperCase();
  const body = typeof init?.body === 'string' ? JSON.parse(init.body) : undefined;
  calls.push({ method, path: url.pathname, query: url.search, body });
  const p = url.pathname;
  if (p === '/api/soar/settings') return json(settings(true));
  if (p === '/api/soar/packs') return json(catalog());
  if (p === '/api/soar/connections') return json({ connections: [connection()] });
  if (p === '/api/soar/runs') return json({ runs: [], limit: 100, offset: 0 });
  if (p === `/api/soar/flows/${FLOW_ID}` && method === 'GET') return json(current);
  if (p === `/api/soar/flows/${FLOW_ID}` && method === 'PUT') return json({ ...current, ...(body as object), version: 4 });
  if (p === `/api/soar/flows/${FLOW_ID}/test`) return json({ id: 'r0000000-0000-4000-8000-000000000010', flow_id: FLOW_ID, status: 'queued', dry_run: true, created_at: '2026-10-26T12:00:00Z', admission: { would_dedupe: false, cooldown_until: null } });
  if (p === '/api/rules' && method === 'GET') {
    const all = [
      { id: 'd0000000-0000-4000-8000-000000000001', name: 'Encoded PowerShell', tags: ['attack.t1059.001'], mode: 'alerting' },
      { id: 'd0000000-0000-4000-8000-000000000002', name: 'Impossible travel', tags: ['identity'], mode: 'alerting' },
    ];
    const term = (url.searchParams.get('search') ?? '').toLowerCase();
    return json(all.filter((r) => r.name.toLowerCase().includes(term)).slice(0, Number(url.searchParams.get('limit') ?? 50)));
  }
  if (p === '/api/rules/r1' && method === 'GET') return json({ id: 'r1', name: 'Suspicious PowerShell', tags: ['attack.t1059.001', 'windows'], mode: 'alerting' });
  if (p === `/api/soar/flows/${FLOW_ID}/run`) return json({ id: 'r0000000-0000-4000-8000-000000000009', flow_id: FLOW_ID, status: 'queued', dry_run: true, created_at: '2026-10-26T12:00:00Z' });
  if (p === '/api/soar/flows/validate-search' && method === 'POST') {
    return validateSearch ? json(validateSearch) : json({ error: { code: 'NOT_FOUND', message: 'no route' } }, 404);
  }
  if (p === '/api/rules/validate') return json({ ...validateRule, effective_mode: 'scheduled', creates_materialized_view: false, mode_reason: '', realtime_eligible: false, referenced_fields: [] });
  if (p === '/api/alerts') {
    return json([
      { id: ALERT_ID, rule_id: 'r1', rule_name: 'Suspicious PowerShell', severity: 'high', status: 'new', matched_events: [{ host: 'FIN-LT-0388', user: 'jdoe', src_ip: '10.20.4.17' }], created_at: '2026-10-26T11:00:00Z' },
      { id: 'a0000000-0000-4000-8000-000000000002', rule_id: 'r2', rule_name: 'Other', severity: 'low', status: 'new', matched_events: [], created_at: '2026-10-26T10:00:00Z' },
    ]);
  }
  if (p === '/api/cases') return json({ cases: [{ id: CASE_ID, case_number: 42, title: 'Ransomware on FIN', severity: 'critical', status: 'in_progress', alert_count: 1, entity_count: 1, created_at: '2026-10-26T09:00:00Z' }], total_count: 1, limit: 10, offset: 0 });
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
const block = (id: string) => screen.getAllByTestId('flow-step').find((b) => b.getAttribute('data-step-id') === id)!;
const inspector = () => screen.getByTestId('flow-inspector');
async function ready() {
  await screen.findByTestId('flow-canvas');
  await waitFor(() => expect(within(block('lookup')).getByText('Get host details · CrowdStrike')).toBeTruthy());
}
/** Open a sentence/picker token and click one of its options. */
async function choose(token: string, option: string | RegExp) {
  fireEvent.click(screen.getByRole('button', { name: token }));
  const list = await screen.findByRole('listbox', { name: `${token} options` });
  fireEvent.click(within(list).getByRole('option', { name: option }));
}
/** The stored expression (the canvas label carries it as its title). */
const preview = () => screen.getByTestId('branch-sentence').getAttribute('title');
async function savedDefinition() {
  fireEvent.click(screen.getByRole('button', { name: 'Save draft' }));
  await waitFor(() => expect(calls.some((c) => c.method === 'PUT')).toBe(true));
  return (calls.find((c) => c.method === 'PUT')!.body as { definition: ReturnType<typeof definition> }).definition;
}

// jsdom lacks these; the Radix Select used by the rule picker calls them.
const proto = Element.prototype as unknown as Record<string, unknown>;
proto.scrollIntoView ??= () => {};
proto.hasPointerCapture ??= () => false;
proto.releasePointerCapture ??= () => {};

beforeEach(() => {
  calls = [];
  perms.denied.clear();
  validateRule = { valid: true, errors: [] };
  validateSearch = { valid: true, errors: [] };
  current = flow({ status: 'draft', definition: definition(), trigger: { on: 'alert', match: null, cron: null } });
  setAccessToken('test-bearer', 3600);
  vi.stubGlobal('fetch', vi.fn(fakeServer));
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('branch condition easy mode', () => {
  test('canvas and inspector show the sentence; tokens write the existing expr strings', async () => {
    renderEditor();
    await ready();
    expect(screen.getByTestId('branch-sentence').textContent).toBe('When Alert → Severity is one of high, critical');
    fireEvent.click(block('route'));
    const easy = screen.getByTestId('condition-easy');
    expect(within(easy).getByRole('button', { name: 'Condition field' }).textContent).toContain('Alert → Severity');
    expect(within(easy).getByRole('button', { name: 'Condition operator' }).textContent).toContain('is one of');
    expect(screen.queryByText('truthy')).toBeNull();
    expect(screen.queryByText('Expression')).toBeNull();
    // Easy mode is jargon-free: no raw expression line under the sentence.
    expect(within(easy).queryByText(/flow_input/)).toBeNull();

    await choose('Condition operator', /^is$/);
    expect(preview()).toBe('flow_input.alert.severity = high');
    await choose('Condition value', /critical/);
    expect(preview()).toBe('flow_input.alert.severity = critical');

    // A field without known values gets a typed free-text token.
    fireEvent.click(screen.getByRole('button', { name: 'Condition field' }));
    fireEvent.change(await screen.findByLabelText('Search fields'), { target: { value: 'source ip' } });
    fireEvent.click(within(screen.getByRole('listbox', { name: 'Condition field options' })).getByRole('option', { name: /Source IP/ }));
    const value = screen.getByLabelText('Condition value') as HTMLInputElement;
    expect(value.getAttribute('aria-invalid')).toBe('true');
    const err = screen.getByText(/Enter one IP address/);
    expect(value.getAttribute('aria-describedby')).toBe(err.id);
    // Matching is exact, so a CIDR range is refused and never written.
    fireEvent.change(value, { target: { value: '10.0.0.0/8' } });
    expect(screen.getByText(/Ranges are not supported/)).toBeTruthy();
    expect(preview()).toBe('flow_input.alert.entities.src_ip = critical');
    // An invalid keystroke keeps the sentence: no flip to advanced.
    fireEvent.change(value, { target: { value: '10.0.0.1"' } });
    expect(screen.getByTestId('condition-easy')).toBeTruthy();
    expect((screen.getByLabelText('Condition value') as HTMLInputElement).value).toBe('10.0.0.1"');
    fireEvent.change(value, { target: { value: '10.0.0.1' } });
    expect(screen.queryByText(/Enter one IP address/)).toBeNull();
    expect(preview()).toBe('flow_input.alert.entities.src_ip = 10.0.0.1');
    // "is true" is only offered for boolean fields.
    fireEvent.click(screen.getByRole('button', { name: 'Condition operator' }));
    expect(within(await screen.findByRole('listbox', { name: 'Condition operator options' })).queryByRole('option', { name: /is true/ })).toBeNull();
    fireEvent.keyDown(screen.getByRole('listbox', { name: 'Condition operator options' }), { key: 'Escape' });

    const def = await savedDefinition();
    expect((def.value.modules[2].value as { branches: Array<{ expr: string }> }).branches[0].expr).toBe('flow_input.alert.entities.src_ip = 10.0.0.1');
  });

  test('a quote or comma typed into a value token never flips the sentence to advanced', async () => {
    renderEditor();
    await ready();
    fireEvent.click(block('route'));
    fireEvent.click(screen.getByRole('button', { name: 'Condition field' }));
    fireEvent.change(await screen.findByLabelText('Search fields'), { target: { value: 'host' } });
    fireEvent.keyDown(screen.getByLabelText('Search fields'), { key: 'Enter' });
    await choose('Condition operator', /^is$/);
    const value = screen.getByLabelText('Condition value') as HTMLInputElement;
    fireEvent.change(value, { target: { value: 'FIN-LT' } });
    expect(preview()).toBe('flow_input.alert.entities.host = FIN-LT');
    for (const bad of ['FIN-LT"', '"', 'FIN-LT, X', 'FIN]']) {
      fireEvent.change(screen.getByLabelText('Condition value'), { target: { value: bad } });
      expect(screen.getByTestId('condition-easy')).toBeTruthy();
      expect((screen.getByLabelText('Condition value') as HTMLInputElement).value).toBe(bad);
      expect(screen.getByLabelText('Condition value').getAttribute('aria-invalid')).toBe('true');
      expect(preview()).toBe('flow_input.alert.entities.host = FIN-LT');
    }
    // Blur drops the invalid draft back to the stored value.
    fireEvent.blur(screen.getByLabelText('Condition value'));
    expect((screen.getByLabelText('Condition value') as HTMLInputElement).value).toBe('FIN-LT');
    // Same for chips.
    await choose('Condition operator', /is one of/);
    const add = screen.getByLabelText('Condition values') as HTMLInputElement;
    fireEvent.change(add, { target: { value: 'x"' } });
    fireEvent.keyDown(add, { key: 'Enter' });
    expect(screen.getByTestId('condition-easy')).toBeTruthy();
    expect(preview()).toBe('flow_input.alert.entities.host in [FIN-LT]');
  });

  test('"is one of" chips refuse commas with a visible error', async () => {
    renderEditor();
    await ready();
    fireEvent.click(block('route'));
    fireEvent.click(screen.getByRole('button', { name: 'Condition field' }));
    fireEvent.change(await screen.findByLabelText('Search fields'), { target: { value: 'host' } });
    fireEvent.keyDown(screen.getByLabelText('Search fields'), { key: 'Enter' });
    expect(screen.getByRole('button', { name: 'Condition field' }).textContent).toContain('Alert → Host');
    const add = screen.getByLabelText('Condition values') as HTMLInputElement;
    fireEvent.change(add, { target: { value: 'a,b' } });
    expect(screen.getByText(/Commas are not allowed/)).toBeTruthy();
    fireEvent.keyDown(add, { key: 'Enter' });
    expect(preview()).toBe('flow_input.alert.entities.host in [high, critical]');
    fireEvent.change(add, { target: { value: 'FIN-LT-0388' } });
    fireEvent.keyDown(add, { key: 'Enter' });
    expect(preview()).toBe('flow_input.alert.entities.host in [high, critical, FIN-LT-0388]');
  });

  test('keyboard: Tab never accepts a suggestion; arrows drive the menus', async () => {
    const user = userEvent.setup();
    renderEditor();
    await ready();
    fireEvent.click(block('lookup'));
    fireEvent.click(screen.getByRole('button', { name: 'hostname advanced' }));
    const raw = screen.getByRole('combobox', { name: 'hostname expression' }) as HTMLInputElement;
    await user.click(raw);
    expect(screen.queryByRole('listbox', { name: 'hostname expression suggestions' })).toBeNull();
    await user.tab();
    await user.tab();
    expect(raw.value).toBe('');
    // Typing opens suggestions; Tab without arrowing still just moves on.
    await user.click(raw);
    await user.type(raw, 'flow_input.alert.entities.ho');
    expect(screen.getByRole('listbox', { name: 'hostname expression suggestions' })).toBeTruthy();
    await user.tab();
    expect(raw.value).toBe('flow_input.alert.entities.ho');
    // Arrowing into the list makes Tab accept, and the input names the active option.
    await user.click(raw);
    await user.type(raw, 's');
    await user.keyboard('{ArrowDown}');
    expect(raw.getAttribute('aria-activedescendant')).toBeTruthy();
    expect(document.getElementById(raw.getAttribute('aria-activedescendant')!)?.textContent).toContain('flow_input.alert.entities.host');
    await user.keyboard('{Tab}');
    expect(raw.value).toBe('flow_input.alert.entities.host');

    // Sentence menus: arrows + Enter.
    fireEvent.click(block('route'));
    await user.click(screen.getByRole('button', { name: 'Condition operator' }));
    const ops = await screen.findByRole('listbox', { name: 'Condition operator options' });
    await waitFor(() => expect(document.activeElement).toBe(ops));
    await user.keyboard('{ArrowUp}{Enter}');
    expect(preview()).toBe('flow_input.alert.severity = high');
  });

  test('canvas label: friendly names for catalog paths, mono raw path otherwise', async () => {
    renderEditor();
    await ready();
    fireEvent.click(block('route'));
    fireEvent.click(screen.getByRole('button', { name: 'Advanced condition' }));
    fireEvent.change(screen.getByRole('combobox', { name: 'Condition' }), { target: { value: 'flow_input.custom.flag' } });
    const label = screen.getByTestId('branch-sentence');
    expect(label.textContent).toBe('When flow_input.custom.flag is true');
    expect(within(label).getByText('flow_input.custom.flag').className).toContain('font-mono');
  });

  test('easy ↔ advanced round-trips without rewriting; unrepresentable text stays advanced', async () => {
    renderEditor();
    await ready();
    fireEvent.click(block('route'));
    fireEvent.click(screen.getByRole('button', { name: 'Advanced condition' }));
    const raw = () => screen.getByRole('combobox', { name: 'Condition' }) as HTMLInputElement;
    expect(raw().value).toBe('flow_input.alert.severity in [high, critical]');

    fireEvent.change(raw(), { target: { value: 'lower flow_input.alert.title' } });
    expect((screen.getByRole('button', { name: 'Advanced condition' }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText(/can't represent it exactly/)).toBeTruthy();

    fireEvent.change(raw(), { target: { value: 'flow_input.alert.severity = low' } });
    fireEvent.click(screen.getByRole('button', { name: 'Advanced condition' }));
    expect(screen.getByRole('button', { name: 'Condition value' }).textContent).toContain('low');
    fireEvent.click(screen.getByRole('button', { name: 'Advanced condition' }));
    expect(raw().value).toBe('flow_input.alert.severity = low');

    // A stored expression the sentence can't show opens in advanced, untouched.
    fireEvent.change(raw(), { target: { value: 'flow_input.alert.severity == high' } });
    fireEvent.click(block('lookup'));
    fireEvent.click(block('route'));
    expect(screen.getByTestId('condition-advanced')).toBeTruthy();
    expect(raw().value).toBe('flow_input.alert.severity == high');
    const def = await savedDefinition();
    expect((def.value.modules[2].value as { branches: Array<{ expr: string }> }).branches[0].expr).toBe('flow_input.alert.severity == high');
  });

  test('autocomplete suggests catalog paths for a partially typed path', async () => {
    renderEditor();
    await ready();
    fireEvent.click(block('route'));
    fireEvent.click(screen.getByRole('button', { name: 'Advanced condition' }));
    const raw = screen.getByRole('combobox', { name: 'Condition' }) as HTMLInputElement;
    fireEvent.focus(raw);
    fireEvent.change(raw, { target: { value: 'results.spread.summary.c' } });
    const list = screen.getByRole('listbox', { name: 'Condition suggestions' });
    const opts = within(list).getAllByRole('option').map((o) => o.textContent);
    expect(opts[0]).toContain('results.spread.summary.count');
    // Steps after the branch are not in scope.
    expect(opts.join()).not.toContain('results.note');
    fireEvent.keyDown(raw, { key: 'Enter' });
    expect(raw.value).toBe('results.spread.summary.count');
  });
});

describe('action input mappings', () => {
  test('"Use a field" picks a catalog path; Advanced shows the raw {{ }} expression', async () => {
    renderEditor();
    await ready();
    fireEvent.click(block('lookup'));
    expect(within(inspector()).getByRole('tab', { name: 'Type a value' })).toBeTruthy();
    expect(within(inspector()).getByRole('tab', { name: 'Use a field' }).getAttribute('aria-selected')).toBe('true');
    await choose('hostname field', /^Host/);
    expect(screen.getByRole('button', { name: 'hostname field' }).textContent).toContain('Alert → Host');
    fireEvent.click(screen.getByRole('button', { name: 'hostname advanced' }));
    const raw = screen.getByRole('combobox', { name: 'hostname expression' }) as HTMLInputElement;
    expect(raw.value).toBe('flow_input.alert.entities.host');
    fireEvent.change(raw, { target: { value: 'coalesce flow_input.alert.entities.host results.spread.rows' } });
    // Helpers can't show in the picker: easy mode is locked, nothing rewritten.
    expect((screen.getByRole('button', { name: 'hostname advanced' }) as HTMLButtonElement).disabled).toBe(true);
    const def = await savedDefinition();
    expect((def.value.modules[1].value as { input_transforms: unknown }).input_transforms).toEqual({ hostname: { type: 'expr', expr: 'coalesce flow_input.alert.entities.host results.spread.rows' } });
  });
});

describe('search step', () => {
  const content = () => document.querySelector('[data-testid="search-query"] .cm-content') as HTMLElement;
  test('insert field writes a {{ }} binding shown as a chip; validate shows success and parse errors', async () => {
    renderEditor();
    await ready();
    fireEvent.click(block('spread'));
    await waitFor(() => expect(content()).toBeTruthy());
    await choose('Insert field', /^Host/);
    // Easy mode: the binding is a chip labelled with the field name; no braces on screen.
    await waitFor(() => expect(content().querySelector('[data-binding="flow_input.alert.entities.host"]')?.textContent).toBe('Alert → Host'));
    expect(content().textContent).toBe('process_name=powershell.exe Alert → Host');
    // Advanced shows the raw stored text.
    fireEvent.click(screen.getByRole('button', { name: 'Advanced query' }));
    await waitFor(() => expect(content().textContent).toBe('process_name=powershell.exe {{flow_input.alert.entities.host}}'));
    // The canvas summary uses the same chip.
    expect(within(block('spread')).getByText('Alert → Host').getAttribute('data-binding')).toBe('flow_input.alert.entities.host');

    // Validate compiles the step server-side exactly as save does: raw bindings, window, limit and scope.
    fireEvent.click(screen.getByRole('button', { name: 'Validate query' }));
    expect((await screen.findByTestId('query-valid')).textContent).toBe('The flow will accept this search step.');
    const req = calls.find((c) => c.path === '/api/soar/flows/validate-search')!;
    expect(req.body).toEqual({
      query: 'process_name=powershell.exe {{flow_input.alert.entities.host}}',
      window: '24h',
      limit: 100,
      trigger: 'alert',
      prior_steps: [],
      in_loop: false,
    });
    expect(calls.some((c) => c.path === '/api/rules/validate')).toBe(false);

    // SearchValidation errors render with their location; window/limit errors name the option.
    validateSearch = {
      valid: false,
      errors: [{ field: 'query', message: "unexpected '|'", start: 28, end: 29, line: 1, column: 29 }],
    };
    fireEvent.click(screen.getByRole('button', { name: 'Validate query' }));
    await waitFor(() => expect(screen.getByTestId('query-errors').textContent).toBe("line 1, column 29: unexpected '|'"));
    expect(screen.queryByTestId('query-valid')).toBeNull();
    validateSearch = { valid: false, errors: [{ field: 'window', message: 'window must be at most 30d', start: null, end: null, line: null, column: null }] };
    fireEvent.click(screen.getByRole('button', { name: 'Validate query' }));
    await waitFor(() => expect(screen.getByTestId('query-errors').textContent).toBe('Time range: window must be at most 30d'));

    const def = await savedDefinition();
    expect(def.value.modules[0].value.query).toBe('process_name=powershell.exe {{flow_input.alert.entities.host}}');
  });

  test('without validate-search (older API) Validate falls back to a syntax-only local check', async () => {
    validateSearch = null;
    renderEditor();
    await ready();
    fireEvent.click(block('spread'));
    await waitFor(() => expect(content()).toBeTruthy());
    const view = EditorView.findFromDOM(content())!;
    const setQuery = (q: string) => act(() => { view.dispatch({ changes: { from: 0, to: view.state.doc.length, insert: q } }); });
    setQuery('process_name=powershell.exe earliest=-7d');
    fireEvent.click(screen.getByRole('button', { name: 'Validate query' }));
    expect((await screen.findByTestId('query-errors')).textContent).toContain("Remove earliest=-7d. The step's time window sets the search range.");
    setQuery('host={{alert.entities.host');
    fireEvent.click(screen.getByRole('button', { name: 'Validate query' }));
    await waitFor(() => expect(screen.getByTestId('query-errors').textContent).toContain('missing its closing }}'));
    expect(calls.some((c) => c.path === '/api/rules/validate')).toBe(false);
    // A clean query is parsed via the marker skeleton and never called "valid".
    setQuery('process_name=powershell.exe host={{alert.entities.host}}');
    fireEvent.click(screen.getByRole('button', { name: 'Validate query' }));
    expect((await screen.findByTestId('query-checked')).textContent).toBe("No nPL syntax errors found. The flow's Validate runs the full check.");
    expect(calls.find((c) => c.path === '/api/rules/validate')!.body).toEqual({ query: 'process_name=powershell.exe host="NANOSOARBOUNDLITERAL0"', detection_mode: 'scheduled' });
  });

  test('a chip is atomic: one Backspace removes the whole binding', async () => {
    renderEditor();
    await ready();
    fireEvent.click(block('spread'));
    await waitFor(() => expect(content()).toBeTruthy());
    await choose('Insert field', /^Host/);
    await waitFor(() => expect(content().querySelector('[data-binding]')).toBeTruthy());
    const view = EditorView.findFromDOM(content())!;
    act(() => {
      view.dispatch({ selection: { anchor: view.state.doc.length } });
      deleteCharBackward(view);
    });
    expect(view.state.doc.toString()).toBe('process_name=powershell.exe ');
    const def = await savedDefinition();
    expect(def.value.modules[0].value.query).toBe('process_name=powershell.exe ');
  });
});

describe('run test dialog', () => {
  test('a real alert is tested through the test endpoint with only its id', async () => {
    renderEditor();
    await ready();
    fireEvent.click(screen.getByRole('button', { name: /Run test/ }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).queryByLabelText('Flow inputs')).toBeNull();
    fireEvent.click(await within(dialog).findByRole('radio', { name: 'Alert Suspicious PowerShell' }));
    // The server builds the production payload; nothing is made up client-side.
    expect(within(dialog).queryByTestId('inputs-preview')).toBeNull();
    expect(within(dialog).queryByLabelText('Case')).toBeNull();
    fireEvent.click(within(dialog).getByRole('button', { name: 'Test with alert' }));
    await waitFor(() => expect(calls.some((c) => c.path === `/api/soar/flows/${FLOW_ID}/test`)).toBe(true));
    expect(calls.find((c) => c.path === `/api/soar/flows/${FLOW_ID}/test`)!.body).toEqual({ alert_id: ALERT_ID });
    expect(calls.some((c) => c.path === `/api/soar/flows/${FLOW_ID}/run`)).toBe(false);
  });

  test('real-alert testing is offered only with soar:manage; otherwise sample values with a hint', async () => {
    renderEditor();
    await ready();
    fireEvent.click(screen.getByRole('button', { name: /Run test/ }));
    let dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByRole('tab', { name: 'Real alert' }).getAttribute('aria-selected')).toBe('true');
    expect(within(dialog).queryByTestId('real-alert-hint')).toBeNull();
    cleanup();
    calls = [];

    perms.denied.add('soar:manage');
    renderEditor();
    await ready();
    fireEvent.click(screen.getByRole('button', { name: /Run test/ }));
    dialog = await screen.findByRole('dialog');
    expect(within(dialog).queryByRole('tab', { name: 'Real alert' })).toBeNull();
    expect(within(dialog).getByRole('tab', { name: 'Sample values' }).getAttribute('aria-selected')).toBe('true');
    expect(within(dialog).getByTestId('real-alert-hint').textContent).toBe('Testing with real alerts needs soar:manage.');
    expect(within(dialog).getByTestId('inputs-form')).toBeTruthy();
    expect(within(dialog).queryByRole('radiogroup', { name: 'Recent alerts' })).toBeNull();
  });

  test('a real run offers no alert picker: only production-shaped sample values', async () => {
    renderEditor();
    await ready();
    fireEvent.click(screen.getByRole('button', { name: 'Run' }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).queryByRole('tab', { name: 'Real alert' })).toBeNull();
    expect(within(dialog).getByTestId('inputs-form')).toBeTruthy();
  });

  test('sample-values form is typed and validated', async () => {
    renderEditor();
    await ready();
    fireEvent.click(screen.getByRole('button', { name: /Run test/ }));
    const dialog = await screen.findByRole('dialog');
    fireEvent.click(within(dialog).getByRole('tab', { name: 'Sample values' }));
    const ip = within(dialog).getByLabelText('alert.entities.src_ip') as HTMLInputElement;
    expect(ip.value).toBe('10.20.4.17');
    fireEvent.change(ip, { target: { value: 'not-an-ip' } });
    const err = within(dialog).getByText(/Enter one IP address/);
    expect(ip.getAttribute('aria-describedby')).toBe(err.id);
    expect((within(dialog).getByRole('button', { name: 'Start dry run' }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(ip, { target: { value: '192.0.2.7' } });
    fireEvent.change(within(dialog).getByLabelText('alert.entities.user'), { target: { value: '' } });
    // Rule fields come from a detection rule, never typed.
    expect(within(dialog).queryByLabelText('alert.tags')).toBeNull();
    await waitFor(() => expect(calls.some((c) => c.path === '/api/alerts')).toBe(true));
    fireEvent.click(within(dialog).getByRole('button', { name: 'Rule' }));
    // Before typing, the options are the rules behind recent detection alerts.
    const opts = await screen.findByRole('listbox', { name: 'Rule options' });
    fireEvent.click(within(opts).getByRole('option', { name: /^Suspicious PowerShell/ }));
    await waitFor(() => expect(calls.some((c) => c.path === '/api/rules/r1')).toBe(true));
    await waitFor(() => expect((within(dialog).getByRole('button', { name: 'Start dry run' }) as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(within(dialog).getByRole('button', { name: 'Start dry run' }));
    await waitFor(() => expect(calls.some((c) => c.path === `/api/soar/flows/${FLOW_ID}/run`)).toBe(true));
    const inputs = (calls.find((c) => c.path === `/api/soar/flows/${FLOW_ID}/run`)!.body as { inputs: { alert: Record<string, unknown> } }).inputs;
    expect(inputs.alert.severity).toBe('high');
    expect(inputs.alert).toMatchObject({ rule_id: 'r1', rule_name: 'Suspicious PowerShell', title: 'Suspicious PowerShell', tags: ['attack.t1059.001', 'windows'], kind: 'detection' });
    // No full rule listing: nothing was searched.
    expect(calls.some((c) => c.path === '/api/rules')).toBe(false);
    expect((inputs.alert.entities as Record<string, unknown>).src_ip).toBe('192.0.2.7');
    // An emptied entity is null, as the trigger sends it.
    expect((inputs.alert.entities as Record<string, unknown>).user).toBeNull();
    // Event triggers send the production shape only: no extra custom paths.
    expect(Object.keys(inputs).sort()).toEqual(['alert']);
  });

  test('rule picker searches all rules as you type: debounced, limit 20, no extra fetch on pick', async () => {
    renderEditor();
    await ready();
    fireEvent.click(screen.getByRole('button', { name: /Run test/ }));
    const dialog = await screen.findByRole('dialog');
    fireEvent.click(within(dialog).getByRole('tab', { name: 'Sample values' }));
    fireEvent.click(within(dialog).getByRole('button', { name: 'Rule' }));
    const box = await screen.findByLabelText('Search rules');
    fireEvent.change(box, { target: { value: 'e' } });
    fireEvent.change(box, { target: { value: 'en' } });
    fireEvent.change(box, { target: { value: 'enc' } });
    const opts = screen.getByRole('listbox', { name: 'Rule options' });
    await waitFor(() => expect(within(opts).getByRole('option', { name: /Encoded PowerShell/ })).toBeTruthy());
    // Debounced: one request for the settled term, capped at 20.
    const searches = calls.filter((c) => c.path === '/api/rules');
    expect(searches.map((c) => c.query)).toEqual(['?search=enc&limit=20']);
    expect(within(opts).queryByRole('option', { name: /Impossible travel/ })).toBeNull();
    // Keyboard: Enter picks the highlighted (first) match.
    fireEvent.keyDown(box, { key: 'Enter' });
    expect(within(dialog).getByRole('button', { name: 'Rule' }).textContent).toContain('Encoded PowerShell');
    fireEvent.click(within(dialog).getByRole('button', { name: 'Start dry run' }));
    await waitFor(() => expect(calls.some((c) => c.path === `/api/soar/flows/${FLOW_ID}/run`)).toBe(true));
    const inputs = (calls.find((c) => c.path === `/api/soar/flows/${FLOW_ID}/run`)!.body as { inputs: { alert: Record<string, unknown> } }).inputs;
    expect(inputs.alert).toMatchObject({ rule_id: 'd0000000-0000-4000-8000-000000000001', rule_name: 'Encoded PowerShell', title: 'Encoded PowerShell', tags: ['attack.t1059.001'] });
    // The search result carried the tags: no per-rule fetch.
    expect(calls.some((c) => c.path.startsWith('/api/rules/'))).toBe(false);
  });

  test('case triggers pick a case: inputs carry the case; attaching is an explicit choice', async () => {
    current = flow({ status: 'draft', definition: definition(), trigger: { on: 'case', match: null, cron: null } });
    renderEditor();
    await ready();
    fireEvent.click(screen.getByRole('button', { name: /Run test/ }));
    const dialog = await screen.findByRole('dialog');
    await act(async () => {
      fireEvent.click(await within(dialog).findByRole('radio', { name: 'Case 42' }));
    });
    // Dry runs attach by default; the checkbox shows it.
    expect(within(dialog).getByRole('checkbox', { name: 'Attach run to case' }).getAttribute('aria-checked')).toBe('true');
    fireEvent.click(within(dialog).getByRole('button', { name: 'Start dry run' }));
    await waitFor(() => expect(calls.some((c) => c.path === `/api/soar/flows/${FLOW_ID}/run`)).toBe(true));
    expect(calls.find((c) => c.path === `/api/soar/flows/${FLOW_ID}/run`)!.body).toEqual({
      inputs: { case: { id: CASE_ID, status: 'in_progress', severity: 'critical' } },
      case_id: CASE_ID,
      dry_run: true,
    });
  });

  test('a real run never attaches the picked case unless asked, and never makes up a transition', async () => {
    current = flow({ status: 'draft', definition: definition(), trigger: { on: 'case', match: null, cron: null } });
    renderEditor();
    await ready();
    fireEvent.click(screen.getByRole('button', { name: 'Run' }));
    const dialog = await screen.findByRole('dialog');
    await act(async () => {
      fireEvent.click(await within(dialog).findByRole('radio', { name: 'Case 42' }));
    });
    expect(within(dialog).getByRole('checkbox', { name: 'Attach run to case' }).getAttribute('aria-checked')).toBe('false');
    // case.transitioned needs a previous status a pick can't know: sample values only.
    fireEvent.click(within(dialog).getByRole('tab', { name: 'Case status changed' }));
    expect(within(dialog).queryByRole('tab', { name: 'Recent case' })).toBeNull();
    fireEvent.click(within(dialog).getByRole('tab', { name: 'Case created' }));
    fireEvent.click(within(dialog).getByRole('tab', { name: 'Recent case' }));
    fireEvent.click(await within(dialog).findByRole('radio', { name: 'Case 42' }));
    fireEvent.click(within(dialog).getByRole('button', { name: 'Run flow' }));
    await waitFor(() => expect(calls.some((c) => c.path === `/api/soar/flows/${FLOW_ID}/run`)).toBe(true));
    expect(calls.find((c) => c.path === `/api/soar/flows/${FLOW_ID}/run`)!.body).toEqual({
      inputs: { case: { id: CASE_ID, status: 'in_progress', severity: 'critical' } },
      dry_run: false,
    });
  });
});
