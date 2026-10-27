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
import { catalog, connection, httpError, pack, settings } from './fixtures';

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
    getFlow: vi.fn(),
    validateFlow: vi.fn(),
    updateFlow: vi.fn(),
    getApprovals: vi.fn(),
    getApproval: vi.fn(),
    approve: vi.fn(),
    reject: vi.fn(),
    installPack: vi.fn(),
    removePack: vi.fn(),
    applyUpstreamUpdate: vi.fn(),
    testConnection: vi.fn(),
    deleteConnection: vi.fn(),
    createConnection: vi.fn(),
    updateConnection: vi.fn(),
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
});
afterEach(cleanup);


describe('Capabilities', () => {
  test('loading', async () => {
    mock.soarApi.getCatalog.mockImplementation(never);
    renderAt('/automation/capabilities');
    expect(await screen.findByRole('heading', { name: 'Capabilities' })).toBeTruthy();
    expect(screen.getAllByRole('status', { name: 'Loading' }).length).toBeGreaterThan(0);
  });
  test('empty', async () => {
    mock.soarApi.getCatalog.mockResolvedValue(catalog([]));
    renderAt('/automation/capabilities');
    expect(await screen.findByText('No packs are entitled for this tenant')).toBeTruthy();
  });
  test('error', async () => {
    mock.soarApi.getCatalog.mockRejectedValue(httpError(500));
    renderAt('/automation/capabilities');
    expect(await screen.findByText('Could not load the catalog')).toBeTruthy();
  });
  test('data: map cell detail, packs install, connections', async () => {
    mock.soarApi.getCatalog.mockResolvedValue(catalog([pack(), pack({ name: 'okta', display_name: 'Okta', vendor: 'Okta', installed: false, installed_version: null })]));
    mock.soarApi.installPack.mockResolvedValue(catalog());
    renderAt('/automation/capabilities');
    const map = await screen.findByTestId('capability-map');
    fireEvent.click(within(map).getByRole('button', { name: 'Host × Contain' }));
    const detail = await screen.findByTestId('cap-detail');
    expect(within(detail).getAllByText('Contain host')).toHaveLength(2);
    expect(within(detail).getAllByTestId('cap-provider')).toHaveLength(2);
    expect(within(detail).getByRole('button', { name: /Run on a host/ })).toBeTruthy();
    expect(within(detail).getByRole('button', { name: 'Install 1.2.0' })).toBeTruthy();
    expect(await screen.findByTestId('cap-wiring')).toBeTruthy();
    expect(screen.getAllByTestId('wiring-row')).toHaveLength(1);

    fireEvent.click(screen.getByRole('tab', { name: 'Packs' }));
    expect(await screen.findAllByTestId('pack-row')).toHaveLength(2);
    fireEvent.click(screen.getByRole('button', { name: 'Install' }));
    const dialog = await screen.findByRole('alertdialog');
    fireEvent.click(within(dialog).getByRole('button', { name: 'Install' }));
    await waitFor(() => expect(mock.soarApi.installPack).toHaveBeenCalledWith('okta', '1.2.0'));

    fireEvent.click(screen.getByRole('tab', { name: 'Connections' }));
    expect(await screen.findAllByTestId('connection-row')).toHaveLength(1);
    expect(screen.getByText('Falcon US-1')).toBeTruthy();
  });
  test('map: a meaningful pair with no provider is a gap', async () => {
    renderAt('/automation/capabilities');
    const map = await screen.findByTestId('capability-map');
    fireEvent.click(within(map).getByRole('button', { name: 'Domain × Block' }));
    expect(await screen.findByText(/No installed or available pack provides this/)).toBeTruthy();
  });
  test('packs: upgrade confirm lists server changes, then applies the upstream version', async () => {
    mock.soarApi.getCatalog.mockResolvedValue(catalog([pack({ upstream_changed: true, upstream_version: '1.3.0', change_summary: 'Added: Get containment status. Changed: Contain host: optional reason.' })]));
    mock.soarApi.applyUpstreamUpdate.mockResolvedValue({});
    renderAt('/automation/capabilities?tab=packs');
    fireEvent.click(await screen.findByRole('button', { name: 'Upgrade' }));
    const dialog = await screen.findByRole('alertdialog');
    expect(within(dialog).getByText('1.2.0 → 1.3.0')).toBeTruthy();
    expect(within(dialog).getByText('Get containment status')).toBeTruthy();
    fireEvent.click(within(dialog).getByRole('button', { name: 'Upgrade to 1.3.0' }));
    await waitFor(() => expect(mock.soarApi.applyUpstreamUpdate).toHaveBeenCalledWith('crowdstrike', '1.3.0'));
  });
  test('packs: row opens the pack sheet with actions', async () => {
    renderAt('/automation/capabilities?tab=packs');
    fireEvent.click(await screen.findByText('CrowdStrike Falcon'));
    const sheet = await screen.findByRole('dialog', { name: 'CrowdStrike Falcon' });
    fireEvent.click(within(sheet).getByRole('button', { name: /Contain host/ }));
    expect(within(sheet).getByText('Always required')).toBeTruthy();
    expect(within(sheet).getByRole('button', { name: /Run action/ })).toBeTruthy();
  });
  test('NAN-4556: a withdrawn pack can be removed through the confirm', async () => {
    mock.soarApi.getCatalog.mockResolvedValue(catalog([pack({ withdrawn: true })]));
    mock.soarApi.removePack.mockResolvedValue({ deleted: true });
    renderAt('/automation/capabilities?tab=packs');
    fireEvent.click(await screen.findByText('CrowdStrike Falcon'));
    const sheet = await screen.findByRole('dialog', { name: 'CrowdStrike Falcon' });
    fireEvent.click(within(sheet).getByRole('button', { name: 'Remove pack' }));
    const confirm = await screen.findByRole('alertdialog');
    expect(within(confirm).getByText('Remove CrowdStrike Falcon?')).toBeTruthy();
    // Opening the confirm sends nothing; only the destructive confirm does.
    expect(mock.soarApi.removePack).not.toHaveBeenCalled();
    const go = within(confirm).getByRole('button', { name: 'Remove pack' });
    expect(go.className).toContain('bg-red-600');
    fireEvent.click(within(confirm).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('alertdialog')).toBeNull());
    expect(mock.soarApi.removePack).not.toHaveBeenCalled();
    fireEvent.click(within(sheet).getByRole('button', { name: 'Remove pack' }));
    const again = await screen.findByRole('alertdialog');
    fireEvent.click(within(again).getByRole('button', { name: 'Remove pack' }));
    await waitFor(() => expect(mock.soarApi.removePack).toHaveBeenCalledWith('crowdstrike'));
  });
  test('without soar:manage, manage controls are locked with a reason', async () => {
    mock.perms = new Set(['soar:view', 'soar:run']);
    mock.soarApi.getCatalog.mockResolvedValue(catalog([pack({ name: 'okta', installed: false, installed_version: null })]));
    renderAt('/automation/capabilities?tab=packs');
    const btn = await screen.findByRole('button', { name: 'Install' });
    expect((btn as HTMLButtonElement).disabled).toBe(true);
    expect(btn.parentElement?.getAttribute('title')).toBe('Requires soar:manage');
  });
  test('connections empty and error', async () => {
    mock.soarApi.getConnections.mockResolvedValue({ connections: [] });
    renderAt('/automation/capabilities');
    fireEvent.click(await screen.findByRole('tab', { name: 'Connections' }));
    expect(await screen.findByText('No connections')).toBeTruthy();
    cleanup();
    mock.soarApi.getConnections.mockRejectedValue(httpError(500));
    renderAt('/automation/capabilities');
    fireEvent.click(await screen.findByRole('tab', { name: 'Connections' }));
    expect(await screen.findByText('Could not load connections')).toBeTruthy();
  });
  test('connections: create validates, then posts write-only credentials', async () => {
    mock.soarApi.createConnection.mockResolvedValue(connection());
    renderAt('/automation/capabilities?tab=connections');
    fireEvent.click(await screen.findByRole('button', { name: /New connection/ }));
    const form = await screen.findByRole('dialog', { name: 'Set up connection' });
    fireEvent.click(within(form).getByRole('button', { name: 'Create connection' }));
    expect(await within(form).findByText('3 fields need attention')).toBeTruthy();
    expect(mock.soarApi.createConnection).not.toHaveBeenCalled();
    fireEvent.change(within(form).getByLabelText('Label'), { target: { value: 'Falcon EU' } });
    fireEvent.change(within(form).getByLabelText('Base URL'), { target: { value: 'https://eu.example.test' } });
    fireEvent.change(within(form).getByLabelText('Client secret'), { target: { value: 's3cret' } });
    expect((within(form).getByRole('button', { name: 'Test connection' }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(within(form).getByRole('button', { name: 'Create connection' }));
    await waitFor(() => expect(mock.soarApi.createConnection).toHaveBeenCalledWith({
      pack_name: 'crowdstrike', label: 'Falcon EU', config: { base_url: 'https://eu.example.test' }, credentials: { client_secret: 's3cret' },
    }));
  });
  test('connections: edit keeps stored credentials unless replaced', async () => {
    mock.soarApi.updateConnection.mockResolvedValue(connection());
    renderAt('/automation/capabilities?tab=connections');
    fireEvent.click(await screen.findByText('Falcon US-1'));
    const sheet = await screen.findByRole('dialog', { name: 'Falcon US-1' });
    fireEvent.click(within(sheet).getByRole('button', { name: /Edit/ }));
    const form = await screen.findByTestId('connection-form');
    expect(within(form).getByText('Configured')).toBeTruthy();
    fireEvent.change(within(form).getByLabelText('Label'), { target: { value: 'Falcon US-1 prod' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save changes' }));
    await waitFor(() => expect(mock.soarApi.updateConnection).toHaveBeenCalledWith('c0000000-0000-4000-8000-000000000001', {
      label: 'Falcon US-1 prod', config: { base_url: 'https://api.example.test' },
    }));
  });
  test('connections: test runs the stored test action and shows the result', async () => {
    mock.soarApi.testConnection.mockResolvedValue({ status: 'failed', message: 'Okta rejected the token (401).', outputs: null, tested_at: new Date().toISOString() });
    renderAt('/automation/capabilities?tab=connections&conn=c0000000-0000-4000-8000-000000000001');
    const sheet = await screen.findByRole('dialog', { name: 'Falcon US-1' });
    expect(within(sheet).getByText(/Not tested yet/)).toBeTruthy();
    fireEvent.click(within(sheet).getByRole('button', { name: /Test connection/ }));
    await waitFor(() => expect(mock.soarApi.testConnection).toHaveBeenCalledWith('c0000000-0000-4000-8000-000000000001'));
    expect(await within(sheet).findByText('Okta rejected the token (401).')).toBeTruthy();
  });
  test('connections: delete is blocked by server dependencies', async () => {
    mock.soarApi.getConnections.mockResolvedValue({ connections: [connection({ can_delete: false, active_runs: 2 })] });
    renderAt('/automation/capabilities?tab=connections&conn=c0000000-0000-4000-8000-000000000001');
    const sheet = await screen.findByRole('dialog', { name: 'Falcon US-1' });
    fireEvent.click(within(sheet).getByRole('button', { name: /Delete/ }));
    const dialog = await screen.findByRole('alertdialog');
    expect(within(dialog).getByTestId('delete-deps').textContent).toMatch(/2 active runs/);
    expect((within(dialog).getByRole('button', { name: 'Deletion blocked' }) as HTMLButtonElement).disabled).toBe(true);
  });
  test('connections: delete needs the acknowledgement', async () => {
    mock.soarApi.deleteConnection.mockResolvedValue(undefined);
    renderAt('/automation/capabilities?tab=connections&conn=c0000000-0000-4000-8000-000000000001');
    const sheet = await screen.findByRole('dialog', { name: 'Falcon US-1' });
    fireEvent.click(within(sheet).getByRole('button', { name: /Delete/ }));
    const dialog = await screen.findByRole('alertdialog');
    const confirm = within(dialog).getByRole('button', { name: 'Delete connection' }) as HTMLButtonElement;
    expect(confirm.disabled).toBe(true);
    fireEvent.click(within(dialog).getByLabelText('Acknowledge connection delete'));
    fireEvent.click(confirm);
    await waitFor(() => expect(mock.soarApi.deleteConnection).toHaveBeenCalledWith('c0000000-0000-4000-8000-000000000001'));
  });
  test('demo: no connections tab, no install buttons', async () => {
    mock.demo = true;
    mock.soarApi.getCatalog.mockResolvedValue(catalog([pack({ name: 'okta', installed: false, installed_version: null })]));
    renderAt('/automation/capabilities');
    await screen.findByRole('heading', { name: 'Capabilities' });
    expect(screen.queryByRole('tab', { name: 'Connections' })).toBeNull();
    fireEvent.click(screen.getByRole('tab', { name: 'Packs' }));
    await screen.findAllByTestId('pack-row');
    expect(screen.queryByRole('button', { name: 'Install' })).toBeNull();
    expect(mock.soarApi.getConnections).not.toHaveBeenCalled();
  });
});
