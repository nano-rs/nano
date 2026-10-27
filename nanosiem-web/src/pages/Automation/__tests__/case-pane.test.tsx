// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
//
// NAN-4540 / NAN-4546 — case linkage: runs filtered by case_id, open gates
// from suspended runs, the receipt wall, and the verb palette prefilling the
// Run action sheet.
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import type { EntityTypeSummary } from '@/lib/api';
import { approval, catalog, connection, httpError, pack, run, runDetail } from './fixtures';

const mock = vi.hoisted(() => ({
  demo: false,
  perms: new Set(['soar:view', 'soar:run', 'soar:approve']),
  soarApi: {
    getRuns: vi.fn(),
    getRun: vi.fn(),
    getCatalog: vi.fn(),
    getConnections: vi.fn(),
    getFlows: vi.fn(),
    getApprovals: vi.fn(),
    queueAction: vi.fn(),
    approve: vi.fn(),
    reject: vi.fn(),
  },
}));

vi.mock('@/lib/api', () => ({ api: { soar: mock.soarApi } }));
vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({
    hasPermission: (p: string) => mock.perms.has(p),
    hasAnyPermission: (ps: string[]) => ps.some((p) => mock.perms.has(p)),
    isDemoUser: mock.demo,
    user: { id: 'me' },
  }),
}));

import { CaseAutomationPane } from '../CaseAutomationPane';
import type { SoarGate } from '../soar-gate';

const CASE = '9a000000-0000-4000-8000-000000000009';
const gate = (demo = false): SoarGate => ({ state: 'enabled', demo, tenant: 't1', retry: () => {} });
const entities: EntityTypeSummary[] = [
  { entity_type: 'host', count: 1, entities: [{ entity_type: 'host', entity_value: 'ws-0142' }] },
] as unknown as EntityTypeSummary[];

function renderPane(g = gate()) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <CaseAutomationPane caseId={CASE} entities={entities} gate={g} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  mock.demo = false;
  mock.perms = new Set(['soar:view', 'soar:run', 'soar:approve']);
  for (const fn of Object.values(mock.soarApi)) fn.mockReset();
  mock.soarApi.getCatalog.mockResolvedValue(catalog());
  mock.soarApi.getConnections.mockResolvedValue({ connections: [connection()] });
  mock.soarApi.getRuns.mockResolvedValue({ runs: [], limit: 100, offset: 0 });
  mock.soarApi.getFlows.mockResolvedValue({ flows: [], event_overflow_count: 0, last_event_overflow_at: null, admission_backpressure: null });
  mock.soarApi.getApprovals.mockResolvedValue({ approvals: [], limit: 100, offset: 0 });
});
afterEach(cleanup);

test('requests only this case’s runs; empty state', async () => {
  renderPane();
  expect(await screen.findByText('No automation has run on this case.')).toBeTruthy();
  expect(mock.soarApi.getRuns).toHaveBeenCalledWith({ limit: 100, case_id: CASE });
});

test('error state', async () => {
  mock.soarApi.getRuns.mockRejectedValue(httpError(500));
  renderPane();
  expect(await screen.findByText('Could not load runs')).toBeTruthy();
});

test('suspended run surfaces its pending approval gate', async () => {
  mock.soarApi.getRuns.mockResolvedValue({ runs: [run({ status: 'suspended', case_id: CASE })], limit: 100, offset: 0 });
  mock.soarApi.getRun.mockResolvedValue(runDetail({ status: 'suspended', approvals: [approval()] }));
  renderPane();
  expect(await screen.findByTestId('approval-card')).toBeTruthy();
  expect(screen.getByText('Waiting on approval')).toBeTruthy();
});

test('verb palette prefills the sheet with the entity and case', async () => {
  mock.soarApi.queueAction.mockResolvedValue(run({ id: 'new', dry_run: true }));
  renderPane();
  await screen.findByText('No automation has run on this case.');
  fireEvent.click(screen.getByRole('button', { name: 'Actions for ws-0142' }));
  const palette = await screen.findByTestId('verb-palette');
  await waitFor(() => expect(within(palette).getByText('Look up')).toBeTruthy());
  fireEvent.click(within(palette).getByText('Look up'));
  const dialog = await screen.findByTestId('run-action-dialog');
  expect((within(dialog).getByLabelText('hostname') as HTMLInputElement).value).toBe('ws-0142');
  expect((within(dialog).getByLabelText('Case ID') as HTMLInputElement).value).toBe(CASE);
  fireEvent.click(within(dialog).getByRole('button', { name: 'Preview' }));
  await waitFor(() =>
    expect(mock.soarApi.queueAction).toHaveBeenCalledWith({
      connection_id: connection().id,
      action: 'get_host',
      inputs: { hostname: 'ws-0142' },
      case_id: CASE,
      dry_run: true,
    }),
  );
  expect(await within(dialog).findByText('Dry run queued')).toBeTruthy();
});

test('destructive request needs the explicit acknowledgement', async () => {
  mock.soarApi.queueAction.mockResolvedValue(run({ id: 'r-new', status: 'suspended' }));
  renderPane();
  await screen.findByText('No automation has run on this case.');
  fireEvent.click(screen.getByRole('button', { name: 'Actions for ws-0142' }));
  fireEvent.click(await within(await screen.findByTestId('verb-palette')).findByText('Contain'));
  const dialog = await screen.findByTestId('run-action-dialog');
  fireEvent.click(within(dialog).getByRole('button', { name: 'Request run' }));
  const confirm = await screen.findByRole('alertdialog');
  const go = within(confirm).getByRole('button', { name: 'Contain host ws-0142' }) as HTMLButtonElement;
  expect(go.disabled).toBe(true);
  expect(mock.soarApi.queueAction).not.toHaveBeenCalled();
  fireEvent.click(within(confirm).getByRole('checkbox', { name: 'Acknowledge destructive action' }));
  expect(go.disabled).toBe(false);
  fireEvent.click(go);
  await waitFor(() =>
    expect(mock.soarApi.queueAction).toHaveBeenCalledWith(expect.objectContaining({ action: 'contain_host', dry_run: false, case_id: CASE })),
  );
});

test('right-click opens the palette too; Escape closes it', async () => {
  renderPane();
  await screen.findByText('No automation has run on this case.');
  fireEvent.contextMenu(screen.getByRole('button', { name: 'Actions for ws-0142' }));
  const palette = await screen.findByTestId('verb-palette');
  expect(within(palette).getByText('Opens Run action prefilled · approval follows server policy')).toBeTruthy();
  fireEvent.keyDown(palette, { key: 'Escape' });
  await waitFor(() => expect(screen.queryByTestId('verb-palette')).toBeNull());
});

test('palette lists unavailable packs with the reason, after usable ones', async () => {
  mock.soarApi.getCatalog.mockResolvedValue(
    catalog([pack(), pack({ name: 'defender', display_name: 'Defender', vendor: 'Microsoft', installed: false, installed_version: null })]),
  );
  renderPane();
  await screen.findByText('No automation has run on this case.');
  fireEvent.click(screen.getByRole('button', { name: 'Actions for ws-0142' }));
  const palette = await screen.findByTestId('verb-palette');
  await waitFor(() => expect(within(palette).getAllByText('Pack not installed').length).toBe(2));
  const items = within(palette).getAllByRole('menuitem') as HTMLButtonElement[];
  expect(items.map((b) => b.disabled)).toEqual([false, false, true, true]);
});

test('without soar:run: Run action is gated, palette says why', async () => {
  mock.perms = new Set(['soar:view']);
  renderPane();
  await screen.findByText('No automation has run on this case.');
  const gated = screen.getByRole('button', { name: /Run action/ }) as HTMLButtonElement;
  expect(gated.disabled).toBe(true);
  expect(gated.parentElement?.getAttribute('title')).toBe('Requires soar:run');
  fireEvent.click(screen.getByRole('button', { name: 'Actions for ws-0142' }));
  const palette = await screen.findByTestId('verb-palette');
  await waitFor(() => expect(within(palette).getAllByText('Requires soar:run').length).toBeGreaterThan(0));
  expect(mock.soarApi.getConnections).not.toHaveBeenCalled();
});

test('wall: receipts with outcome, approver and inverse; decided gates', async () => {
  const r1 = run({ id: 'r1000000-0000-4000-8000-000000000001', case_id: CASE, status: 'succeeded' });
  const base = pack();
  const lift = { ...base.actions[1], name: 'lift_containment', display_name: 'Lift containment', effect: 'write', rollback: null };
  mock.soarApi.getCatalog.mockResolvedValue(catalog([pack({ actions: [...base.actions, lift] })]));
  mock.soarApi.getRuns.mockResolvedValue({ runs: [r1], limit: 100, offset: 0 });
  mock.soarApi.getApprovals.mockImplementation(({ status }: { status: string }) =>
    Promise.resolve({
      approvals:
        status === 'approved'
          ? [approval({ id: 'a-ok', run_id: r1.id, status: 'approved', decided_by: 'm.okafor', decided_at: new Date().toISOString(), reason: 'Confirmed beacon' })]
          : [],
      limit: 100,
      offset: 0,
    }),
  );
  renderPane();
  const receipt = await screen.findByTestId('receipt');
  expect(within(receipt).getByText('Contain')).toBeTruthy();
  expect(within(receipt).getByText('Done')).toBeTruthy();
  await waitFor(() => expect(within(receipt).getByText('approved by m.okafor')).toBeTruthy());
  expect(screen.getByTestId('wall-decided').textContent).toContain('Confirmed beacon');
  fireEvent.click(within(receipt).getByRole('button', { name: '↺ request inverse' }));
  const dialog = await screen.findByTestId('run-action-dialog');
  expect(within(dialog).getByText('Lift containment', { selector: 'h2' })).toBeTruthy();
});

test('failed run with an ambiguous step reads as unknown outcome', async () => {
  const r1 = run({ id: 'r2000000-0000-4000-8000-000000000002', case_id: CASE, status: 'failed' });
  mock.soarApi.getRuns.mockResolvedValue({ runs: [r1], limit: 100, offset: 0 });
  const d = runDetail({ ...r1 });
  d.steps[0].status = 'ambiguous';
  mock.soarApi.getRun.mockResolvedValue(d);
  renderPane();
  expect(await screen.findByText('Unknown · verify target')).toBeTruthy();
});

test('decisions are sorted by expiry', async () => {
  const r1 = run({ id: 'r3000000-0000-4000-8000-000000000003', case_id: CASE, status: 'suspended' });
  mock.soarApi.getRuns.mockResolvedValue({ runs: [r1], limit: 100, offset: 0 });
  const later = approval({ id: 'a-later', expires_at: new Date(Date.now() + 50 * 60_000).toISOString() });
  const sooner = approval({ id: 'a-sooner', expires_at: new Date(Date.now() + 8 * 60_000).toISOString() });
  mock.soarApi.getRun.mockResolvedValue(runDetail({ ...r1, approvals: [later, sooner] }));
  renderPane();
  await screen.findAllByTestId('approval-card');
  expect(screen.getByText('Needs a decision · 2')).toBeTruthy();
  const ids = Array.from(screen.getByTestId('case-decisions').querySelectorAll(':scope > [id^="apr-"]')).map((e) => e.id);
  expect(ids).toEqual(['apr-a-sooner', 'apr-a-later']);
});

test('demo: no run controls, no connections or approval reads', async () => {
  mock.demo = true;
  renderPane(gate(true));
  await screen.findByText('No automation has run on this case.');
  expect(screen.queryByRole('button', { name: /Run action/ })).toBeNull();
  expect(mock.soarApi.getConnections).not.toHaveBeenCalled();
  expect(mock.soarApi.getRun).not.toHaveBeenCalled();
  expect(mock.soarApi.getApprovals).not.toHaveBeenCalled();
});
