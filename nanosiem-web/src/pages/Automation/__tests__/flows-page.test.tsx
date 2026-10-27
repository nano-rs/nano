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
import { catalog, connection, flow, httpError, settings } from './fixtures';

const mock = vi.hoisted(() => ({
  demo: false,
  perms: new Set(['soar:view', 'soar:run', 'soar:manage', 'soar:approve']),
  soarApi: {
    getSettings: vi.fn(),
    getRuns: vi.fn(),
    getRun: vi.fn(),
    cancelRun: vi.fn(),
    getCatalog: vi.fn(),
    getConnections: vi.fn(),
    getFlows: vi.fn(),
    getFlowStats: vi.fn(),
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
  mock.soarApi.getFlowStats.mockRejectedValue(httpError(503));
  mock.soarApi.getApprovals.mockResolvedValue({ approvals: [], limit: 100, offset: 0 });
});
afterEach(cleanup);


describe('Flows', () => {
  test('loading', async () => {
    mock.soarApi.getFlows.mockImplementation(never);
    renderAt('/automation/flows');
    expect(await screen.findByRole('heading', { name: 'Flows' })).toBeTruthy();
    expect(screen.getAllByRole('status', { name: 'Loading' }).length).toBeGreaterThan(0);
  });
  test('empty', async () => {
    renderAt('/automation/flows');
    expect(await screen.findByText('No flows yet')).toBeTruthy();
  });
  test('error', async () => {
    mock.soarApi.getFlows.mockRejectedValue(httpError(500));
    renderAt('/automation/flows');
    expect(await screen.findByText('Could not load flows')).toBeTruthy();
  });
  test('data + backpressure notice', async () => {
    mock.soarApi.getFlows.mockResolvedValue({ ...noFlows, flows: [flow(), flow({ id: 'f2', name: 'Draft flow', status: 'draft' })], admission_backpressure: { reason: 'queue full', since: '2026-10-25T10:00:00Z' } });
    renderAt('/automation/flows');
    expect(await screen.findAllByTestId('flow-row')).toHaveLength(2);
    expect(screen.getByText('Trigger admission is throttled')).toBeTruthy();
    fireEvent.click(screen.getByRole('tab', { name: /Draft/ }));
    expect(screen.getAllByTestId('flow-row')).toHaveLength(1);
  });
  test('NAN-4544: 24h counts come from flow stats; a loaded flow missing from them ran 0', async () => {
    mock.soarApi.getFlows.mockResolvedValue({ ...noFlows, flows: [flow(), flow({ id: 'f2', name: 'Quiet flow' })] });
    mock.soarApi.getFlowStats.mockResolvedValue({ window_hours: 24, since: '2026-10-24T14:00:00Z', flows: [{ flow_id: flow().id, runs: 37, succeeded: 35, failed: 2 }] });
    renderAt('/automation/flows');
    const rows = await screen.findAllByTestId('flow-row');
    expect(await within(rows[0]).findByText('37 runs · 24h')).toBeTruthy();
    expect(within(rows[0]).getByText('37 runs · 24h').getAttribute('title')).toBe('35 succeeded · 2 failed');
    expect(within(rows[1]).getByText('0 runs · 24h')).toBeTruthy();
    expect(mock.soarApi.getFlowStats).toHaveBeenCalledTimes(1);
  });
  test('NAN-4544: flow stats unavailable shows an em dash', async () => {
    mock.soarApi.getFlows.mockResolvedValue({ ...noFlows, flows: [flow()] });
    renderAt('/automation/flows');
    const [row] = await screen.findAllByTestId('flow-row');
    await vi.waitFor(() => expect(mock.soarApi.getFlowStats).toHaveBeenCalled());
    expect(within(row).getByText('—', { selector: '.text-right' })).toBeTruthy();
  });
  // Inputs mapped so local checks pass and Activate only waits on Validate.
  const validDefinition = {
    summary: 'Contain',
    description: '',
    value: {
      modules: [
        { id: 'lookup', value: { type: 'action', pack: 'crowdstrike', action: 'get_host', connection: 'c0000000-0000-4000-8000-000000000001', input_transforms: { hostname: { type: 'expr', expr: 'flow_input.host' } } } },
        { id: 'gate', value: { type: 'approval', prompt: 'Contain this host?', options: ['contain', 'skip'] } },
        { id: 'contain', value: { type: 'action', pack: 'crowdstrike', action: 'contain_host', connection: 'c0000000-0000-4000-8000-000000000001', input_transforms: { hostname: { type: 'expr', expr: 'flow_input.host' } } } },
      ],
    },
  };
  test('flow view: editor canvas, validate, then activate via confirm', async () => {
    mock.soarApi.getFlow.mockResolvedValue(flow({ status: 'draft', definition: validDefinition }));
    mock.soarApi.validateFlow.mockResolvedValue({ valid: true, module_count: 3, summary: 'valid' });
    mock.soarApi.updateFlow.mockResolvedValue(flow({ status: 'live', version: 4, definition: validDefinition }));
    renderAt('/automation/flows/f0000000-0000-4000-8000-000000000001');
    const canvas = await screen.findByTestId('flow-canvas');
    await waitFor(() => expect(within(canvas).getByText('Get host details · CrowdStrike')).toBeTruthy());
    expect(within(canvas).getByText('Contain this host?')).toBeTruthy();
    const activate = screen.getByRole('button', { name: 'Activate' }) as HTMLButtonElement;
    expect(activate.disabled).toBe(true);
    fireEvent.click(screen.getByRole('button', { name: 'Validate' }));
    await screen.findByText('Valid');
    await waitFor(() => expect((screen.getByRole('button', { name: 'Activate' }) as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(screen.getByRole('button', { name: 'Activate' }));
    const dialog = await screen.findByRole('alertdialog');
    fireEvent.click(within(dialog).getByRole('button', { name: 'Activate' }));
    await waitFor(() => expect(mock.soarApi.updateFlow).toHaveBeenCalled());
    const [, body] = mock.soarApi.updateFlow.mock.calls[0];
    expect(body).toMatchObject({ status: 'live', expected_version: 3 });
  });
  test('flow view: without soar:manage edit controls are locked', async () => {
    mock.perms = new Set(['soar:view', 'soar:run']);
    mock.soarApi.getFlow.mockResolvedValue(flow({ status: 'draft', definition: validDefinition }));
    renderAt('/automation/flows/f0000000-0000-4000-8000-000000000001');
    await screen.findByTestId('flow-canvas');
    for (const name of ['Validate', 'Save draft', 'Activate']) {
      const b = screen.getByRole('button', { name }) as HTMLButtonElement;
      expect(b.disabled).toBe(true);
      expect(b.parentElement?.getAttribute('title')).toBe('Requires soar:manage');
    }
    expect(screen.queryByRole('button', { name: 'Undo' })).toBeNull();
  });
  test('flow view: demo shows no effect controls', async () => {
    mock.demo = true;
    mock.soarApi.getFlow.mockResolvedValue(flow({ status: 'draft' }));
    renderAt('/automation/flows/f0000000-0000-4000-8000-000000000001');
    await screen.findByTestId('flow-canvas');
    for (const name of ['Activate', 'Validate', 'Run', 'Run test', 'Save draft']) {
      expect(screen.queryByRole('button', { name })).toBeNull();
    }
  });
});

