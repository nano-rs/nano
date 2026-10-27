// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
//
// NAN-4540 — per-page loading / empty / error / data states with SOAR on,
// plus the decision-gate rules (self-approval, destructive confirm, 409).
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import type { Capabilities } from '@/hooks/use-capabilities';
import { catalog, connection, httpError, run, runDetail, settings } from './fixtures';

const mock = vi.hoisted(() => ({
  demo: false,
  perms: new Set(['soar:view', 'soar:run', 'soar:manage', 'soar:approve']),
  soarApi: {
    getSettings: vi.fn(),
    getRuns: vi.fn(),
    getRun: vi.fn(),
    getRunVolume: vi.fn(),
    cancelRun: vi.fn(),
    getCatalog: vi.fn(),
    getConnections: vi.fn(),
    getFlows: vi.fn(),
    getFlow: vi.fn(),
    validateFlow: vi.fn(),
    updateFlow: vi.fn(),
    getApprovals: vi.fn(),
    getApproval: vi.fn(),
    approve: vi.fn(),
    reject: vi.fn(),
    installPack: vi.fn(),
    applyUpstreamUpdate: vi.fn(),
    testConnection: vi.fn(),
    deleteConnection: vi.fn(),
  },
}));

function caps(): Capabilities {
  return {
    search: true, cases: false, notebooks: false, risk: false, melod: false, queryCorrection: false,
    customEnrichment: false, agentEnrichment: false, aiTuning: false, playbooks: false, incidents: false,
    siemHealth: true, sso: true, observabilityConvergence: false, iocLists: true, soar: true,
  };
}

vi.mock('@/lib/api', () => ({ api: { soar: mock.soarApi } }));
vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({ edition: 'enterprise', version: 'test', capabilities: caps() }),
}));
vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({
    hasPermission: (p: string) => mock.perms.has(p),
    hasAnyPermission: (ps: string[]) => ps.some((p) => mock.perms.has(p)),
    isDemoUser: mock.demo,
    user: { id: 'me' },
  }),
}));

import {
  AutomationApprovalsRoute,
  AutomationCapabilitiesRoute,
  AutomationFlowRoute,
  AutomationFlowsRoute,
  AutomationRunsRoute,
} from '../index';

function renderAt(path: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/automation/runs" element={<AutomationRunsRoute />} />
          <Route path="/automation/runs/:id" element={<AutomationRunsRoute />} />
          <Route path="/automation/flows" element={<AutomationFlowsRoute />} />
          <Route path="/automation/flows/:id" element={<AutomationFlowRoute />} />
          <Route path="/automation/approvals" element={<AutomationApprovalsRoute />} />
          <Route path="/automation/approvals/:id" element={<AutomationApprovalsRoute />} />
          <Route path="/automation/capabilities" element={<AutomationCapabilitiesRoute />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return client;
}

const never = () => new Promise<never>(() => {});
const noFlows = { flows: [], event_overflow_count: 0, last_event_overflow_at: null, admission_backpressure: null };

beforeEach(() => {
  mock.demo = false;
  mock.perms = new Set(['soar:view', 'soar:run', 'soar:manage', 'soar:approve']);
  for (const fn of Object.values(mock.soarApi)) fn.mockReset();
  mock.soarApi.getSettings.mockResolvedValue(settings(true));
  mock.soarApi.getCatalog.mockResolvedValue(catalog());
  mock.soarApi.getConnections.mockResolvedValue({ connections: [connection()] });
  mock.soarApi.getRuns.mockResolvedValue({ runs: [], limit: 100, offset: 0 });
  mock.soarApi.getFlows.mockResolvedValue(noFlows);
  mock.soarApi.getApprovals.mockResolvedValue({ approvals: [], limit: 100, offset: 0 });
  mock.soarApi.getRun.mockResolvedValue(runDetail());
  mock.soarApi.getRunVolume.mockRejectedValue(httpError(404));
});
afterEach(cleanup);

/** 48 zero buckets ending at the next 30-minute boundary, like the server. */
function volume(hits: Array<[number, { runs: number; failed?: number; waiting?: number; running?: number }]>) {
  const step = 30 * 60_000;
  const until = Math.ceil(Date.now() / step) * step;
  const since = until - 48 * step;
  const buckets = Array.from({ length: 48 }, (_, i) => ({ start: new Date(since + i * step).toISOString(), runs: 0, failed: 0, waiting: 0, running: 0 }));
  for (const [i, b] of hits) Object.assign(buckets[i], { failed: 0, waiting: 0, running: 0, ...b });
  return { since: new Date(since).toISOString(), until: new Date(until).toISOString(), bucket_minutes: 30, total: buckets.reduce((n, b) => n + b.runs, 0), buckets };
}


describe('Runs', () => {
  test('loading', async () => {
    mock.soarApi.getRuns.mockImplementation(never);
    renderAt('/automation/runs');
    expect(await screen.findByRole('heading', { name: 'Runs' })).toBeTruthy();
    expect(screen.getAllByRole('status', { name: 'Loading' }).length).toBeGreaterThan(0);
  });
  test('empty', async () => {
    renderAt('/automation/runs');
    expect(await screen.findByText('No runs yet')).toBeTruthy();
  });
  test('error with retry', async () => {
    mock.soarApi.getRuns.mockRejectedValue(httpError(500));
    renderAt('/automation/runs');
    expect(await screen.findByText('Could not load runs')).toBeTruthy();
    mock.soarApi.getRuns.mockResolvedValue({ runs: [], limit: 100, offset: 0 });
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByText('No runs yet')).toBeTruthy();
  });
  test('data: rows, filters and the changes ledger', async () => {
    mock.soarApi.getRuns.mockResolvedValue({
      runs: [
        run(),
        run({ id: 'r2', action: 'get_host', status: 'failed', error_class: 'vendor_5xx' }),
        run({ id: 'r3', status: 'suspended' }),
      ],
      limit: 100,
      offset: 0,
    });
    renderAt('/automation/runs');
    expect(await screen.findAllByTestId('run-row')).toHaveLength(3);
    expect(screen.getByTestId('runs-volume')).toBeTruthy();
    // The first run is selected by default, like the mock.
    expect(await screen.findByTestId('run-trace')).toBeTruthy();
    // Attention = waiting, unknown outcome or failed.
    fireEvent.click(screen.getByRole('tab', { name: /Attention/ }));
    expect(screen.getAllByTestId('run-row')).toHaveLength(2);
    expect(within(screen.getAllByTestId('run-row')[0]).getByText('Get host details')).toBeTruthy();
    // Changes = write/destructive only: the read-only get_host run drops out.
    fireEvent.click(screen.getByRole('tab', { name: /Changes/ }));
    expect(screen.getAllByTestId('run-row')).toHaveLength(2);
    // Search narrows by target.
    fireEvent.click(screen.getByRole('tab', { name: /All/ }));
    fireEvent.change(screen.getByLabelText('Search runs'), { target: { value: 'nothing-matches' } });
    expect(await screen.findByText('No runs match these filters')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Clear filters' }));
    expect(screen.getAllByTestId('run-row')).toHaveLength(3);
  });
  test('detail pane is its own scroll container with a bounded height chain (NAN-4659)', async () => {
    mock.soarApi.getRun.mockResolvedValue(runDetail());
    renderAt('/automation/runs/r0000000-0000-4000-8000-000000000001');
    const trace = await screen.findByTestId('run-trace');
    const cls = (el: Element | null) => (el?.getAttribute('class') ?? '').split(/\s+/);
    // The scrolling element sits inside the trace and owns overflow.
    const scroller = trace.firstElementChild;
    expect(cls(scroller)).toEqual(expect.arrayContaining(['min-h-0', 'flex-1', 'overflow-auto']));
    // Trace fills the pane; the pane is a bounded flex column.
    expect(cls(trace)).toEqual(expect.arrayContaining(['flex-1', 'min-h-0', 'flex-col']));
    const pane = screen.getByTestId('runs-detail-pane');
    expect(pane.contains(trace)).toBe(true);
    expect(cls(pane)).toEqual(expect.arrayContaining(['flex', 'flex-col', 'min-h-0', 'overflow-hidden']));
    // The grid row is capped to the available height, so neither pane grows past the frame.
    const grid = pane.parentElement;
    expect(cls(grid)).toEqual(expect.arrayContaining(['grid', 'min-h-0', 'flex-1', 'grid-rows-[minmax(0,1fr)]']));
    // The list pane scrolls independently.
    expect(cls(grid!.firstElementChild)).toContain('min-h-0');
    expect(cls(screen.getByTestId('runs-page'))).toEqual(expect.arrayContaining(['h-full', 'min-h-0']));
  });
  test('run trace: steps and not-found', async () => {
    mock.soarApi.getRun.mockResolvedValue(runDetail());
    renderAt('/automation/runs/r0000000-0000-4000-8000-000000000001');
    const trace = await screen.findByTestId('run-trace');
    expect(within(trace).getAllByText('Contain host').length).toBeGreaterThan(0);
    expect(within(trace).getByText('Succeeded')).toBeTruthy();
    expect(within(trace).getAllByTestId('trace-span')).toHaveLength(1);
    cleanup();
    mock.soarApi.getRun.mockRejectedValue(httpError(404));
    renderAt('/automation/runs/missing');
    expect(await screen.findByText('Run not found')).toBeTruthy();
  });
  test('Run action is gated without soar:run', async () => {
    mock.perms.delete('soar:run');
    renderAt('/automation/runs');
    await screen.findByText('No runs yet');
    const button = screen.getByRole('button', { name: /Run action/ }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    expect(button.parentElement?.getAttribute('title')).toBe('Requires soar:run');
  });
  test('demo: no Run action', async () => {
    mock.demo = true;
    renderAt('/automation/runs');
    await screen.findByText('No runs yet');
    expect(screen.queryByRole('button', { name: /Run action/ })).toBeNull();
  });
  test('cancel a running run through the confirm', async () => {
    mock.soarApi.getRuns.mockResolvedValue({ runs: [run({ status: 'running', finished_at: null })], limit: 100, offset: 0 });
    mock.soarApi.getRun.mockResolvedValue(runDetail({ status: 'running', finished_at: null }));
    mock.soarApi.cancelRun.mockResolvedValue(run({ status: 'canceled' }));
    renderAt('/automation/runs');
    const trace = await screen.findByTestId('run-trace');
    fireEvent.click(within(trace).getByRole('button', { name: 'Cancel run' }));
    const dialog = await screen.findByRole('alertdialog');
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel run' }));
    await vi.waitFor(() => expect(mock.soarApi.cancelRun).toHaveBeenCalledWith(run().id));
  });
  test('NAN-4556: histogram reads the server volume, not just the loaded page', async () => {
    mock.soarApi.getRuns.mockResolvedValue({ runs: [run()], limit: 100, offset: 0 });
    mock.soarApi.getRunVolume.mockResolvedValue(volume([[10, { runs: 900, failed: 7 }], [47, { runs: 641, waiting: 2, running: 1 }]]));
    renderAt('/automation/runs');
    const histogram = await screen.findByTestId('runs-volume');
    await vi.waitFor(() => expect(within(histogram).getByText('1,541 runs · 30 min buckets')).toBeTruthy());
    expect(mock.soarApi.getRunVolume).toHaveBeenCalledWith({ hours: 24, bucket_minutes: 30 });
  });
  test('NAN-4556: clicking a bucket lists that bucket from the server', async () => {
    const vol = volume([[10, { runs: 900, failed: 7 }]]);
    const start = vol.buckets[10].start;
    const inside = new Date(Date.parse(start) + 60_000).toISOString();
    mock.soarApi.getRunVolume.mockResolvedValue(vol);
    mock.soarApi.getRuns.mockImplementation(async (q: { created_after?: string } = {}) => (q.created_after
      ? { runs: [run({ id: 'b0000000-0000-4000-8000-0000000000aa', created_at: inside, started_at: inside })], limit: 100, offset: 0 }
      : { runs: [run()], limit: 100, offset: 0 }));
    renderAt('/automation/runs');
    const histogram = await screen.findByTestId('runs-volume');
    await vi.waitFor(() => expect(within(histogram).getByText('900 runs · 30 min buckets')).toBeTruthy());
    fireEvent.click(within(histogram).getAllByRole('button')[10]);
    await vi.waitFor(() => expect(mock.soarApi.getRuns).toHaveBeenCalledWith({
      limit: 100, created_after: start, created_before: new Date(Date.parse(start) + 30 * 60_000).toISOString(),
    }));
    await vi.waitFor(() => expect(screen.getAllByTestId('run-row')).toHaveLength(1));
    expect(screen.getByText(/window · 1 of 900/)).toBeTruthy();
  });
  test('NAN-4556: the selected bucket is a time slot, kept when a refetch slides the window', async () => {
    const vol = volume([[10, { runs: 900 }]]);
    const start = vol.buckets[10].start;
    mock.soarApi.getRunVolume.mockResolvedValue(vol);
    const client = renderAt('/automation/runs');
    const histogram = await screen.findByTestId('runs-volume');
    await vi.waitFor(() => expect(within(histogram).getByText('900 runs · 30 min buckets')).toBeTruthy());
    fireEvent.click(within(histogram).getAllByRole('button')[10]);
    expect(within(histogram).getAllByRole('button')[10].getAttribute('aria-pressed')).toBe('true');
    // Next bucket boundary: the server window slides by one bucket.
    const step = 30 * 60_000;
    const slid = { ...vol, since: new Date(Date.parse(vol.since) + step).toISOString(), until: new Date(Date.parse(vol.until) + step).toISOString(),
      buckets: [...vol.buckets.slice(1), { start: new Date(Date.parse(vol.until)).toISOString(), runs: 0, failed: 0, waiting: 0, running: 0 }] };
    mock.soarApi.getRunVolume.mockResolvedValue(slid);
    await client.refetchQueries({ queryKey: ['soar'] });
    await vi.waitFor(() => expect(within(histogram).getAllByRole('button')[9].getAttribute('aria-pressed')).toBe('true'));
    expect(within(histogram).getAllByRole('button')[10].getAttribute('aria-pressed')).toBe('false');
    const windowed = mock.soarApi.getRuns.mock.calls.map((c: unknown[]) => (c[0] as { created_after?: string } | undefined)?.created_after).filter(Boolean);
    expect(new Set(windowed)).toEqual(new Set([start]));
  });
  test('NAN-4556: histogram falls back to the loaded page when volume fails', async () => {
    mock.soarApi.getRuns.mockResolvedValue({ runs: [run({ created_at: new Date().toISOString() })], limit: 100, offset: 0 });
    renderAt('/automation/runs');
    const histogram = await screen.findByTestId('runs-volume');
    expect(within(histogram).getByText('1 runs · 30 min buckets')).toBeTruthy();
  });
  test('NAN-4544: trace shows the requester name, affected entities and the approval deadline', async () => {
    const waiting = runDetail({
      status: 'suspended', finished_at: null, requested_by: 'u2', requested_by_name: 'Ana Chen', affected_entities: 3,
      steps: [{ ...runDetail().steps[0], status: 'awaiting_approval', finished_at: null, finished_at_ms: null, deadline_at: '2026-10-25T15:16:00Z' }],
      approvals: [{ id: 'ap1', run_id: runDetail().id, module_id: 'action', requested_action: { pack: 'crowdstrike', action: 'contain_host', inputs: {} }, requested_by: 'u2', requested_source: 'user', ambiguous: false, status: 'pending', created_at: '2026-10-25T14:16:00Z', expires_at: '2026-10-25T15:16:00Z', decided_by: null, decided_at: null, choice: null, reason: null }],
    });
    mock.soarApi.getRuns.mockResolvedValue({ runs: [run({ status: 'suspended', requested_by: 'u2', requested_by_name: 'Ana Chen', affected_entities: 3 })], limit: 100, offset: 0 });
    mock.soarApi.getRun.mockResolvedValue(waiting);
    renderAt('/automation/runs');
    const trace = await screen.findByTestId('run-trace');
    expect(within(trace).getAllByText('Ana Chen').length).toBeGreaterThan(0);
    const affected = within(trace).getByText('Affected entities');
    expect(affected.parentElement?.textContent).toContain('3');
    // Rows read the name too, never the raw id.
    expect(within(screen.getAllByTestId('run-row')[0]).getByText(/Ana Chen/)).toBeTruthy();
    fireEvent.click(within(trace).getAllByTestId('trace-span')[0]);
    expect(await within(trace).findByText(/deadline 15:16 UTC/)).toBeTruthy();
  });
  test('NAN-4544: affected entities and names fall back when absent', async () => {
    mock.soarApi.getRuns.mockResolvedValue({ runs: [run({ requested_by: 'u2' })], limit: 100, offset: 0 });
    mock.soarApi.getRun.mockResolvedValue(runDetail({ requested_by: 'u2' }));
    renderAt('/automation/runs');
    const trace = await screen.findByTestId('run-trace');
    expect(within(trace).getByText('Affected entities').parentElement?.textContent).toContain('—');
    expect(within(trace).getAllByText('u2').length).toBeGreaterThan(0);
  });
  test('NAN-4556: case numbers label the trace and the Case filter', async () => {
    const caseId = 'c4se0000-0000-4000-8000-000000000001';
    mock.soarApi.getRuns.mockResolvedValue({ runs: [run({ case_id: caseId, case_number: 1042 })], limit: 100, offset: 0 });
    mock.soarApi.getRun.mockResolvedValue(runDetail({ case_id: caseId, case_number: 1042 }));
    renderAt('/automation/runs');
    const trace = await screen.findByTestId('run-trace');
    const link = await within(trace).findByRole('link', { name: 'CASE-1042' });
    expect(link.getAttribute('href')).toBe(`/cases/${caseId}`);
  });
});
