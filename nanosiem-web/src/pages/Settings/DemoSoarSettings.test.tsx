// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
const mock = vi.hoisted(() => ({
  soar: true,
  roles: ['demo_analyst'],
  demoIdentity: false,
  listFlows: vi.fn(),
  listRuns: vi.fn(),
  listPacks: vi.fn(),
  runDetail: vi.fn(),
  getSettings: vi.fn(),
  getRecipients: vi.fn(),
  getMailTransport: vi.fn(),
  getUpstreamUpdates: vi.fn(),
  applyUpstreamUpdate: vi.fn(),
  applyAllUpstreamUpdates: vi.fn(),
}));
vi.mock('@/lib/api', () => ({ api: { soar: mock } }));
vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({
    user: { roles: mock.roles, demo: mock.demoIdentity ? {} : undefined },
    hasPermission: () => true,
  }),
}));
vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({ capabilities: { soar: mock.soar } }),
}));
vi.mock('@/hooks/useDocumentTitle', () => ({ useDocumentTitle: vi.fn() }));
vi.mock('@/hooks/use-mobile', () => ({ useIsMobile: () => false }));
import { SoarSettings } from './SoarSettings';
const runId = '11111111-1111-4111-8111-111111111111';
beforeEach(() => {
  vi.resetAllMocks();
  mock.soar = true;
  mock.roles = ['demo_analyst'];
  mock.demoIdentity = false;
  mock.listFlows.mockResolvedValue({
    flows: [
      {
        id: runId,
        name: 'Triage demo',
        version: 1,
        status: 'live',
        definition: { value: { modules: [] } },
      },
    ],
  });
  mock.listRuns.mockResolvedValue({
    runs: [
      {
        id: runId,
        status: 'succeeded',
        dry_run: true,
        created_at: '2026-10-24T17:00:00Z',
        trigger_kind: 'alert',
      },
    ],
  });
  mock.listPacks.mockResolvedValue({
    packs: [
      {
        name: 'notify',
        display_name: 'Notifications',
        vendor: 'nano',
        version: '1',
        installed: true,
      },
    ],
  });
  mock.runDetail.mockResolvedValue({
    steps: [
      {
        id: 'step',
        module_id: 'search',
        phase: 'read',
        status: 'succeeded',
        outputs: { count: 3 },
      },
    ],
  });
});
afterEach(cleanup);
function page() {
  render(
    <QueryClientProvider
      client={
        new QueryClient({ defaultOptions: { queries: { retry: false } } })
      }
    >
      <SoarSettings />
    </QueryClientProvider>,
  );
}
function noConfigReads() {
  expect(mock.getSettings).not.toHaveBeenCalled();
  expect(mock.getRecipients).not.toHaveBeenCalled();
  expect(mock.getMailTransport).not.toHaveBeenCalled();
  expect(mock.getUpstreamUpdates).not.toHaveBeenCalled();
  expect(mock.applyUpstreamUpdate).not.toHaveBeenCalled();
  expect(mock.applyAllUpstreamUpdates).not.toHaveBeenCalled();
}
test('demo role sees real flows, history and catalog without writes or sensitive config requests', async () => {
  page();
  expect(await screen.findByText('Triage demo')).toBeTruthy();
  expect(await screen.findByText('Notifications')).toBeTruthy();
  expect(await screen.findByRole('button', { name: 'View run' })).toBeTruthy();
  expect(
    screen.queryByRole('button', {
      name: /Enable SOAR|Disable SOAR|Send test|Add recipient|Configure|Apply.*update/i,
    }),
  ).toBeNull();
  noConfigReads();
});
test('normalizes the reserved demo role exactly as the server gate does', async () => {
  mock.roles = ['  DeMo_AnAlYsT  '];
  page();
  await screen.findByText('Triage demo');
  noConfigReads();
});
test('demo identity holding an admin role still gets only the read-only view', async () => {
  mock.roles = ['admin'];
  mock.demoIdentity = true;
  page();
  await screen.findByText('Triage demo');
  noConfigReads();
  expect(screen.queryByLabelText('Reason')).toBeNull();
});
test('run details fetch only the selected run and display its step outputs', async () => {
  page();
  fireEvent.click(await screen.findByRole('button', { name: 'View run' }));
  expect(await screen.findByText('search · read · succeeded')).toBeTruthy();
  expect(screen.getByText(/"count": 3/)).toBeTruthy();
  expect(mock.runDetail).toHaveBeenCalledWith(runId);
  noConfigReads();
});
test('empty demo inventories are explicit', async () => {
  mock.listFlows.mockResolvedValue({ flows: [] });
  mock.listRuns.mockResolvedValue({ runs: [] });
  mock.listPacks.mockResolvedValue({ packs: [] });
  page();
  expect(await screen.findByText('No flows yet.')).toBeTruthy();
  expect(await screen.findByText('No runs yet.')).toBeTruthy();
  expect(await screen.findByText('No packs available.')).toBeTruthy();
  noConfigReads();
});
test('failed reads do not open a configuration fallback', async () => {
  mock.listFlows.mockRejectedValue(new Error('Unavailable'));
  page();
  expect(await screen.findByRole('alert')).toBeTruthy();
  noConfigReads();
});
test('capability gate still controls visibility and API queries', () => {
  mock.soar = false;
  page();
  expect(mock.listFlows).not.toHaveBeenCalled();
  expect(mock.listRuns).not.toHaveBeenCalled();
  expect(mock.listPacks).not.toHaveBeenCalled();
  noConfigReads();
});
