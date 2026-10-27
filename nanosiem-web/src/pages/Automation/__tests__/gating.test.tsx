// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
//
// NAN-4540 — Automation is gated by the tenant soar_enabled setting:
// off → no SOAR data request, nav section hidden, routes show a disabled
// state; on → pages load; the Settings → SOAR save (setQueryData on the
// shared key) flips nav and routes without a reload.
import { act, cleanup, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import type { Capabilities } from '@/hooks/use-capabilities';
import { catalog, httpError, settings } from './fixtures';

const mock = vi.hoisted(() => ({
  soar: true,
  demo: false,
  perms: new Set(['soar:view', 'soar:run', 'soar:manage', 'soar:approve']),
  soarApi: {
    getSettings: vi.fn(),
    getRuns: vi.fn(),
    getRun: vi.fn(),
    getCatalog: vi.fn(),
    getConnections: vi.fn(),
    getFlows: vi.fn(),
    getFlow: vi.fn(),
    getApprovals: vi.fn(),
    getApproval: vi.fn(),
  },
}));

function caps(soar: boolean): Capabilities {
  return {
    search: true, cases: false, notebooks: false, risk: false, melod: false, queryCorrection: false,
    customEnrichment: false, agentEnrichment: false, aiTuning: false, playbooks: false, incidents: false,
    siemHealth: true, sso: true, observabilityConvergence: false, iocLists: true, soar,
  };
}

vi.mock('@/lib/api', () => ({ api: { soar: mock.soarApi } }));
vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({ edition: 'enterprise', version: 'test', capabilities: caps(mock.soar) }),
}));
vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({
    hasPermission: (p: string) => mock.perms.has(p),
    hasAnyPermission: (ps: string[]) => ps.some((p) => mock.perms.has(p)),
    isDemoUser: mock.demo,
    user: { id: 'me' },
  }),
}));

import { browserTenantRuntime } from '@/lib/tenant-runtime';
import { AutomationRunsRoute, AutomationFlowsRoute, AutomationApprovalsRoute, AutomationCapabilitiesRoute } from '../index';
import { useAutomationNav } from '../automation-nav';
import { soarSettingsKey } from '../soar-gate';

function NavProbe() {
  const { items } = useAutomationNav();
  return <nav data-testid="nav-probe">{items.map((i) => <span key={i.href}>{i.name}</span>)}</nav>;
}

function renderAt(path: string, client = new QueryClient({ defaultOptions: { queries: { retry: false } } })) {
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <NavProbe />
        <Routes>
          <Route path="/automation/runs" element={<AutomationRunsRoute />} />
          <Route path="/automation/runs/:id" element={<AutomationRunsRoute />} />
          <Route path="/automation/flows" element={<AutomationFlowsRoute />} />
          <Route path="/automation/approvals" element={<AutomationApprovalsRoute />} />
          <Route path="/automation/capabilities" element={<AutomationCapabilitiesRoute />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return client;
}

const DATA_CALLS = ['getRuns', 'getRun', 'getCatalog', 'getConnections', 'getFlows', 'getFlow', 'getApprovals', 'getApproval'] as const;

function expectNoSoarDataCalls() {
  for (const name of DATA_CALLS) expect(mock.soarApi[name], name).not.toHaveBeenCalled();
}

beforeEach(() => {
  mock.soar = true;
  mock.demo = false;
  mock.perms = new Set(['soar:view', 'soar:run', 'soar:manage', 'soar:approve']);
  for (const fn of Object.values(mock.soarApi)) fn.mockReset();
  mock.soarApi.getRuns.mockResolvedValue({ runs: [], limit: 100, offset: 0 });
  mock.soarApi.getCatalog.mockResolvedValue(catalog([]));
  mock.soarApi.getConnections.mockResolvedValue({ connections: [] });
  mock.soarApi.getFlows.mockResolvedValue({ flows: [], event_overflow_count: 0, last_event_overflow_at: null, admission_backpressure: null });
  mock.soarApi.getApprovals.mockResolvedValue({ approvals: [], limit: 100, offset: 0 });
});
afterEach(cleanup);

test.each(['/automation/runs', '/automation/runs/r1', '/automation/flows', '/automation/approvals', '/automation/capabilities'])(
  'disabled: %s shows the disabled state, hides the nav and makes no SOAR data call',
  async (path) => {
    mock.soarApi.getSettings.mockResolvedValue(settings(false));
    renderAt(path);
    expect(await screen.findByTestId('soar-gate-disabled')).toBeTruthy();
    expect(screen.getByText('SOAR is disabled')).toBeTruthy();
    expect(screen.getByRole('link', { name: 'Open Settings → SOAR' }).getAttribute('href')).toBe('/settings/soar');
    expect(screen.getByTestId('nav-probe').textContent).toBe('');
    expectNoSoarDataCalls();
  },
);

test('without the soar capability nothing is requested, not even settings', async () => {
  mock.soar = false;
  renderAt('/automation/runs');
  expect(await screen.findByTestId('soar-gate-unavailable')).toBeTruthy();
  expect(mock.soarApi.getSettings).not.toHaveBeenCalled();
  expectNoSoarDataCalls();
});

test('settings read failure shows a retryable error and still no data calls', async () => {
  mock.soarApi.getSettings.mockRejectedValue(httpError(503));
  renderAt('/automation/flows');
  expect(await screen.findByTestId('soar-gate-error')).toBeTruthy();
  expect(screen.getByRole('button', { name: 'Retry' })).toBeTruthy();
  expectNoSoarDataCalls();
});

test('enabled: nav lists the sections and the runs page loads', async () => {
  mock.soarApi.getSettings.mockResolvedValue(settings(true));
  renderAt('/automation/runs');
  expect(await screen.findByText('No runs yet')).toBeTruthy();
  expect(screen.getByTestId('nav-probe').textContent).toBe('RunsFlowsApprovalsCapabilities');
  expect(mock.soarApi.getRuns).toHaveBeenCalled();
});

test('toggling the setting flips nav and route without a reload', async () => {
  mock.soarApi.getSettings.mockResolvedValue(settings(false));
  const client = renderAt('/automation/runs');
  expect(await screen.findByTestId('soar-gate-disabled')).toBeTruthy();
  expectNoSoarDataCalls();

  // What Settings → SOAR does after a successful save.
  const key = soarSettingsKey(browserTenantRuntime.current().key);
  act(() => client.setQueryData(key, settings(true)));
  expect(await screen.findByText('No runs yet')).toBeTruthy();
  expect(screen.getByTestId('nav-probe').textContent).toContain('Runs');

  act(() => client.setQueryData(key, settings(false)));
  expect(await screen.findByTestId('soar-gate-disabled')).toBeTruthy();
  await waitFor(() => expect(screen.getByTestId('nav-probe').textContent).toBe(''));
});

test('demo principal: the flow list is the probe; 404 means disabled', async () => {
  mock.demo = true;
  mock.soarApi.getFlows.mockRejectedValue(httpError(404));
  renderAt('/automation/runs');
  expect(await screen.findByTestId('soar-gate-disabled')).toBeTruthy();
  expect(mock.soarApi.getSettings).not.toHaveBeenCalled();
  expect(mock.soarApi.getRuns).not.toHaveBeenCalled();
  expect(screen.queryByRole('link', { name: 'Open Settings → SOAR' })).toBeNull();
});

test('demo principal with SOAR on: read views load, no approvals entry, no effect controls', async () => {
  mock.demo = true;
  renderAt('/automation/runs');
  expect(await screen.findByText('No runs yet')).toBeTruthy();
  expect(screen.getByTestId('nav-probe').textContent).toBe('RunsFlowsCapabilities');
  expect(screen.queryByRole('button', { name: /Run action/ })).toBeNull();
  expect(mock.soarApi.getApprovals).not.toHaveBeenCalled();
  expect(mock.soarApi.getConnections).not.toHaveBeenCalled();
});
