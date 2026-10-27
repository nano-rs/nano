// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
//
// NAN-4540 — per-page loading / empty / error / data states with SOAR on,
// plus the decision-gate rules (self-approval, destructive confirm, 409).
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import type { Capabilities } from '@/hooks/use-capabilities';
import { approval, catalog, connection, httpError, settings } from './fixtures';

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
  mock.soarApi.getRunVolume.mockRejectedValue(httpError(404));
});
afterEach(cleanup);


describe('Approvals', () => {
  test('loading', async () => {
    mock.soarApi.getApprovals.mockImplementation(never);
    renderAt('/automation/approvals');
    expect(await screen.findByRole('heading', { name: 'Approvals' })).toBeTruthy();
    expect(screen.getAllByRole('status', { name: 'Loading' }).length).toBeGreaterThan(0);
  });
  test('empty', async () => {
    renderAt('/automation/approvals');
    expect(await screen.findByText('Nothing waiting on you')).toBeTruthy();
  });
  test('error', async () => {
    mock.soarApi.getApprovals.mockRejectedValue(httpError(500));
    renderAt('/automation/approvals');
    expect(await screen.findByText('Could not load approvals')).toBeTruthy();
  });
  test('data: destructive approval is hold-to-approve, then posts the decision', async () => {
    mock.soarApi.getApprovals.mockResolvedValue({ approvals: [approval()], limit: 100, offset: 0 });
    mock.soarApi.approve.mockResolvedValue(approval({ status: 'approved' }));
    renderAt('/automation/approvals');
    expect(await screen.findAllByTestId('approval-row')).toHaveLength(1);
    const card = await screen.findByTestId('approval-card');
    fireEvent.change(within(card).getByLabelText('Decision reason'), { target: { value: 'confirmed compromise' } });
    expect(within(card).queryByRole('button', { name: 'Approve' })).toBeNull();
    const hold = within(card).getByTestId('hold-to-approve');
    // A tap is not a decision.
    fireEvent.pointerDown(hold);
    fireEvent.pointerUp(hold);
    await new Promise((r) => setTimeout(r, 200));
    expect(mock.soarApi.approve).not.toHaveBeenCalled();
    // Holding (keyboard) for the full duration decides.
    fireEvent.keyDown(hold, { key: 'Enter' });
    await waitFor(() => expect(mock.soarApi.approve).toHaveBeenCalledWith(approval().id, { reason: 'confirmed compromise' }), { timeout: 3000 });
  });
  test('reject requires a reason', async () => {
    mock.soarApi.getApprovals.mockResolvedValue({ approvals: [approval()], limit: 100, offset: 0 });
    renderAt('/automation/approvals');
    const card = await screen.findByTestId('approval-card');
    fireEvent.click(within(card).getByRole('button', { name: 'Reject' }));
    expect(within(card).getByText('A reason is required to reject.')).toBeTruthy();
    expect(mock.soarApi.reject).not.toHaveBeenCalled();
  });
  test('reason is capped at 2048 bytes', async () => {
    mock.soarApi.getApprovals.mockResolvedValue({ approvals: [approval()], limit: 100, offset: 0 });
    renderAt('/automation/approvals');
    const card = await screen.findByTestId('approval-card');
    fireEvent.change(within(card).getByLabelText('Decision reason'), { target: { value: 'é'.repeat(1100) } });
    expect(within(card).getByText('2200 / 2048 bytes')).toBeTruthy();
    expect((within(card).getByRole('button', { name: 'Reject' }) as HTMLButtonElement).disabled).toBe(true);
  });
  test('self-requested approval cannot be decided here', async () => {
    mock.soarApi.getApprovals.mockResolvedValue({ approvals: [approval({ requested_by: 'me' })], limit: 100, offset: 0 });
    renderAt('/automation/approvals');
    const card = await screen.findByTestId('approval-card');
    expect(within(card).getByText('You requested this; another approver must decide')).toBeTruthy();
    expect(within(card).queryByRole('button', { name: 'Approve' })).toBeNull();
  });
  test('409 on decide shows the lost-race message', async () => {
    mock.soarApi.getApprovals.mockResolvedValue({
      approvals: [approval({ requested_action: { pack: 'crowdstrike', action: 'get_host', inputs: { hostname: 'ws-1' } } })],
      limit: 100,
      offset: 0,
    });
    mock.soarApi.reject.mockRejectedValue(httpError(409));
    renderAt('/automation/approvals');
    const card = await screen.findByTestId('approval-card');
    fireEvent.change(within(card).getByLabelText('Decision reason'), { target: { value: 'not needed' } });
    fireEvent.click(within(card).getByRole('button', { name: 'Reject' }));
    expect(await within(card).findByText(/Another approver decided first/)).toBeTruthy();
  });
  test('NAN-4556: 409 names who decided first from the refetched approval', async () => {
    const pending = approval({ requested_action: { pack: 'crowdstrike', action: 'get_host', inputs: { hostname: 'ws-1' } } });
    mock.soarApi.getApprovals.mockResolvedValue({ approvals: [pending], limit: 100, offset: 0 });
    mock.soarApi.reject.mockRejectedValue(httpError(409));
    mock.soarApi.getApproval.mockResolvedValue({ ...pending, status: 'approved', decided_by: 'u_achen', decided_at: '2026-10-25T14:21:09Z' });
    renderAt('/automation/approvals');
    const card = await screen.findByTestId('approval-card');
    fireEvent.change(within(card).getByLabelText('Decision reason'), { target: { value: 'not needed' } });
    fireEvent.click(within(card).getByRole('button', { name: 'Reject' }));
    expect(await within(card).findByText('u_achen approved at 14:21 UTC first. Your decision was not recorded.')).toBeTruthy();
    expect(mock.soarApi.getApproval).toHaveBeenCalledWith(pending.id);
  });
  test('NAN-4544: requester and decider names replace raw ids', async () => {
    mock.soarApi.getApprovals.mockImplementation(async ({ status }: { status?: string } = {}) => ({
      approvals: status === 'pending' || !status
        ? [approval({ requested_by: 'u7', requested_by_name: 'Mara Okafor', requested_source: 'user' })]
        : [],
      limit: 100, offset: 0,
    }));
    renderAt('/automation/approvals');
    const card = await screen.findByTestId('approval-card');
    expect(within(card).getAllByText(/Mara Okafor/).length).toBeGreaterThan(0);
    expect(within(card).queryByText(/\bu7\b/)).toBeNull();
  });
  test('NAN-4544: 409 uses the decider name', async () => {
    const pending = approval({ requested_action: { pack: 'crowdstrike', action: 'get_host', inputs: { hostname: 'ws-1' } } });
    mock.soarApi.getApprovals.mockResolvedValue({ approvals: [pending], limit: 100, offset: 0 });
    mock.soarApi.reject.mockRejectedValue(httpError(409));
    mock.soarApi.getApproval.mockResolvedValue({ ...pending, status: 'rejected', decided_by: 'u_achen', decided_by_name: 'Ana Chen', decided_at: '2026-10-25T14:21:09Z' });
    renderAt('/automation/approvals');
    const card = await screen.findByTestId('approval-card');
    fireEvent.change(within(card).getByLabelText('Decision reason'), { target: { value: 'not needed' } });
    fireEvent.click(within(card).getByRole('button', { name: 'Reject' }));
    expect(await within(card).findByText('Ana Chen rejected at 14:21 UTC first. Your decision was not recorded.')).toBeTruthy();
  });
  test('NAN-4556: drawer rows use the approval case number', async () => {
    mock.soarApi.getApprovals.mockResolvedValue({
      approvals: [approval({ case_id: 'c4se0000-0000-4000-8000-000000000001', case_number: 1042 })],
      limit: 100,
      offset: 0,
    });
    renderAt('/automation/approvals');
    const row = await screen.findByTestId('approval-row');
    expect(within(row).getByText(/CASE-1042/)).toBeTruthy();
  });
  test('approval option and required note', async () => {
    mock.soarApi.getApprovals.mockResolvedValue({
      approvals: [approval({ requested_action: { prompt: 'Contain?', options: ['contain', 'skip'], note_required_on: 'skip' } })],
      limit: 100,
      offset: 0,
    });
    mock.soarApi.approve.mockResolvedValue(approval({ status: 'approved' }));
    renderAt('/automation/approvals');
    const card = await screen.findByTestId('approval-card');
    const approve = within(card).getByRole('button', { name: 'Approve' }) as HTMLButtonElement;
    expect(approve.disabled).toBe(true);
    fireEvent.click(within(card).getByRole('radio', { name: 'skip' }));
    expect(approve.disabled).toBe(true);
    fireEvent.change(within(card).getByLabelText('Decision reason'), { target: { value: 'benign' } });
    expect(approve.disabled).toBe(false);
    fireEvent.click(approve);
    await waitFor(() => expect(mock.soarApi.approve).toHaveBeenCalledWith(approval().id, { choice: 'skip', reason: 'benign' }));
  });
});

