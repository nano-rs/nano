// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
//
// NAN-4649 — SOAR's running / waiting-on-you counts render in the app-wide
// footer (StatusBar page-status slot), not in a second bar, and only while a
// SOAR route is mounted.
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes, useNavigate } from 'react-router-dom';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import type { Capabilities } from '@/hooks/use-capabilities';
import { LayoutProvider } from '@/contexts/LayoutContext';
import { approval, catalog, connection, httpError, settings } from './fixtures';

const mock = vi.hoisted(() => ({
  perms: new Set(['soar:view', 'soar:run', 'soar:manage', 'soar:approve']),
  soarApi: {
    getSettings: vi.fn(),
    getRuns: vi.fn(),
    getRun: vi.fn(),
    getRunVolume: vi.fn(),
    getCatalog: vi.fn(),
    getConnections: vi.fn(),
    getFlows: vi.fn(),
    getApprovals: vi.fn(),
    getApproval: vi.fn(),
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
    isDemoUser: false,
    user: { id: 'me' },
  }),
}));
vi.mock('@/hooks/use-api', () => ({
  useSiemHealthLatest: () => ({ data: { overall_status: 'healthy' } }),
  useIngestionHistory: () => ({ data: [{ count: 60 }] }),
}));
vi.mock('@/components/layout/AppBreadcrumbs', () => ({ useCurrentPageTitle: () => 'Page' }));

import { AutomationRunsRoute } from '../index';
import { StatusBar } from '@/components/layout/StatusBar';

function Elsewhere() {
  const navigate = useNavigate();
  return <button type="button" onClick={() => navigate('/automation/runs')}>go soar</button>;
}

function renderAt(path: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <LayoutProvider>
          <Routes>
            <Route path="/automation/runs" element={<AutomationRunsRoute />} />
            <Route path="/search" element={<Elsewhere />} />
          </Routes>
          <StatusBar />
        </LayoutProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const footer = () => screen.getByRole('contentinfo');

beforeEach(() => {
  mock.perms = new Set(['soar:view', 'soar:run', 'soar:manage', 'soar:approve']);
  for (const fn of Object.values(mock.soarApi)) fn.mockReset();
  mock.soarApi.getSettings.mockResolvedValue(settings(true));
  mock.soarApi.getCatalog.mockResolvedValue(catalog());
  mock.soarApi.getConnections.mockResolvedValue({ connections: [connection()] });
  mock.soarApi.getRuns.mockResolvedValue({ runs: [], limit: 100, offset: 0 });
  mock.soarApi.getFlows.mockResolvedValue({ flows: [], event_overflow_count: 0, last_event_overflow_at: null, admission_backpressure: null });
  mock.soarApi.getApprovals.mockResolvedValue({ approvals: [approval()], limit: 100, offset: 0 });
  mock.soarApi.getRunVolume.mockRejectedValue(httpError(404));
});
afterEach(cleanup);

test('SOAR route puts running / waiting-on-you counts in the app footer, no second bar', async () => {
  renderAt('/automation/runs');
  const f = footer();
  await waitFor(() => expect(within(f).getByText(/1 waiting on you/)).toBeTruthy());
  expect(within(f).getByText(/0 running/)).toBeTruthy();
  expect(within(f).getByText(/platform healthy/)).toBeTruthy();
  // Exactly one status surface, and it is inside the footer.
  expect(screen.getAllByTestId('automation-status')).toHaveLength(1);
  expect(f.contains(screen.getByTestId('automation-status'))).toBe(true);
  // Waiting > 0 reads amber; the permission chips are gone.
  expect(within(f).getByText(/1 waiting on you/).closest('button')?.className).toContain('text-warn');
  expect(screen.queryByText(/soar:view · soar:manage/)).toBeNull();
});

test('waiting count is not amber at zero', async () => {
  mock.soarApi.getApprovals.mockResolvedValue({ approvals: [], limit: 100, offset: 0 });
  renderAt('/automation/runs');
  const btn = await within(footer()).findByText(/0 waiting on you/);
  await waitFor(() => expect(screen.getByTestId('automation-status')).toBeTruthy());
  expect(btn.closest('button')?.className).not.toContain('text-warn');
});

test('other routes show the default footer, not SOAR counts', async () => {
  renderAt('/search');
  expect(screen.getByText('go soar')).toBeTruthy();
  expect(within(footer()).queryByText(/waiting on you/)).toBeNull();
  expect(within(footer()).getByText('1 events/min')).toBeTruthy();
  // Entering SOAR adds the counts...
  fireEvent.click(screen.getByText('go soar'));
  await waitFor(() => expect(within(footer()).getByText(/waiting on you/)).toBeTruthy());
});

test('leaving SOAR clears the counts from the footer', async () => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  function Leave() {
    const navigate = useNavigate();
    return <button type="button" onClick={() => navigate('/search')}>leave</button>;
  }
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/automation/runs']}>
        <LayoutProvider>
          <Leave />
          <Routes>
            <Route path="/automation/runs" element={<AutomationRunsRoute />} />
            <Route path="/search" element={<div>search page</div>} />
          </Routes>
          <StatusBar />
        </LayoutProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  await waitFor(() => expect(within(footer()).getByText(/waiting on you/)).toBeTruthy());
  fireEvent.click(screen.getByText('leave'));
  await screen.findByText('search page');
  expect(within(footer()).queryByText(/waiting on you/)).toBeNull();
  expect(within(footer()).getByText('1 events/min')).toBeTruthy();
});
