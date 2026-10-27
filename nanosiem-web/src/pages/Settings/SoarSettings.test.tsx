// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
//
// NAN-4462 — Settings → SOAR opt-in: capability gate, admin-only edits,
// revision-checked save with a required reason, 409 refresh path.
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import type { Capabilities } from '@/hooks/use-capabilities';

const mock = vi.hoisted(() => ({
  soar: true,
  admin: true,
  getSettings: vi.fn(),
  updateSettings: vi.fn(),
}));

function caps(soar: boolean): Capabilities {
  return {
    search: true,
    cases: false,
    notebooks: false,
    risk: false,
    melod: false,
    queryCorrection: false,
    customEnrichment: false,
    agentEnrichment: false,
    aiTuning: false,
    playbooks: false,
    incidents: false,
    siemHealth: true,
    sso: true,
    observabilityConvergence: false,
    iocLists: true,
    soar,
  };
}

vi.mock('@/lib/api', () => ({
  api: {
    soar: {
      getSettings: mock.getSettings,
      getUpstreamUpdates: vi.fn().mockResolvedValue({ updates: [], total_count: 0 }),
      updateSettings: mock.updateSettings,
      getRecipients: vi
        .fn()
        .mockResolvedValue({
          recipients: [],
          revision: 0,
          daily_send_cap: 100,
        }),
      getMailTransport: vi
        .fn()
        .mockResolvedValue({
          transport: 'nano',
          smtp: null,
          revision: 0,
          has_password: false,
          nano_mailer_available: true,
        }),
    },
  },
}));
vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({
    edition: 'enterprise',
    version: 'test',
    capabilities: caps(mock.soar),
  }),
}));
vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({
    hasPermission: (p: string) =>
      p === 'soar:view' ||
      (mock.admin && ['settings:system', 'audit:view'].includes(p)),
    hasAnyPermission: (ps: string[]) =>
      ps.includes('soar:view') ||
      (mock.admin && ps.includes('settings:system')),
    isDemoUser: false,
    user: { deployment_mode: 'enterprise_shared' },
  }),
}));
vi.mock('@/hooks/use-tier', () => ({
  useTierContext: () => ({ hasSso: true }),
}));
vi.mock('@/hooks/use-shared-tenant', () => ({ useSharedTenant: () => true }));
vi.mock('@/hooks/useDocumentTitle', () => ({ useDocumentTitle: vi.fn() }));
vi.mock('@/hooks/use-api', () => ({
  useSystemConfig: () => ({
    data: { deployment_mode: 'enterprise_shared', air_gap: false },
  }),
  useRecentAuditChanges: () => ({ data: { entries: [] }, loading: false }),
}));

import { SoarSettings } from './SoarSettings';
import { SettingsLanding } from './SettingsLanding';

const SOAR_DISABLE_WARNING =
  'New runs stop, active runs are canceled and pending approvals expire with reason “soar disabled”. A request already sent to a vendor cannot be undone. History, connections and installed packs stay stored until removed.';

function renderPage(node: React.ReactNode = <SoarSettings />) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>{node}</MemoryRouter>
    </QueryClientProvider>,
  );
}

async function openReason(enabled = false) {
  fireEvent.click(
    await screen.findByRole('button', {
      name: enabled ? 'Disable SOAR…' : 'Enable SOAR…',
    }),
  );
  return screen.findByLabelText('Reason');
}

function httpError(status: number, message: string) {
  return Object.assign(new Error(message), { status });
}

beforeEach(() => {
  mock.soar = true;
  mock.admin = true;
  mock.getSettings.mockReset();
  mock.updateSettings.mockReset();
});
afterEach(cleanup);

test('hidden without the soar capability: no Settings tile and no settings read', () => {
  mock.soar = false;
  renderPage(<SettingsLanding />);
  expect(screen.queryByText('SOAR')).toBeNull();
  cleanup();
  renderPage();
  expect(
    screen.getByText('SOAR is not available for this tenant.'),
  ).toBeTruthy();
  expect(mock.getSettings).not.toHaveBeenCalled();
});

test('the Settings tile is shown with the soar capability', () => {
  renderPage(<SettingsLanding />);
  expect(screen.getByText('SOAR')).toBeTruthy();
});

test('read-only for a non-admin', async () => {
  mock.admin = false;
  mock.getSettings.mockResolvedValue({ soar_enabled: false, revision: 0 });
  renderPage();
  await screen.findByText('Disabled');
  expect(screen.getByText(/Read-only\. Changing SOAR requires/)).toBeTruthy();
  expect(screen.queryByLabelText('Reason')).toBeNull();
  expect(screen.queryByRole('button', { name: 'Enable SOAR' })).toBeNull();
});

test('save sends expected_revision and the reason', async () => {
  mock.getSettings.mockResolvedValue({ soar_enabled: false, revision: 4 });
  mock.updateSettings.mockResolvedValue({ soar_enabled: true, revision: 5 });
  renderPage();
  await openReason();
  const button = screen.getByRole('button', { name: 'Enable SOAR' });
  expect((button as HTMLButtonElement).disabled).toBe(true);
  fireEvent.change(screen.getByLabelText('Reason'), {
    target: { value: '  Pilot automation for phishing  ' },
  });
  await waitFor(() =>
    expect((button as HTMLButtonElement).disabled).toBe(false),
  );
  fireEvent.click(button);
  await screen.findByText('SOAR enabled.');
  expect(mock.updateSettings).toHaveBeenCalledWith({
    soar_enabled: true,
    expected_revision: 4,
    reason: 'Pilot automation for phishing',
  });
  expect(screen.getByText('enabled · revision 5')).toBeTruthy();
});

test('disabling asks for confirmation first', async () => {
  mock.getSettings.mockResolvedValue({ soar_enabled: true, revision: 2 });
  mock.updateSettings.mockResolvedValue({ soar_enabled: false, revision: 3 });
  renderPage();
  fireEvent.change(await openReason(true), {
    target: { value: 'Incident freeze' },
  });
  expect(mock.updateSettings).not.toHaveBeenCalled();
  expect(screen.getByText(SOAR_DISABLE_WARNING)).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Disable SOAR' }));
  await waitFor(() =>
    expect(mock.updateSettings).toHaveBeenCalledWith({
      soar_enabled: false,
      expected_revision: 2,
      reason: 'Incident freeze',
    }),
  );
});

test('409 refetches the setting and asks the user to save again', async () => {
  mock.getSettings.mockResolvedValueOnce({ soar_enabled: false, revision: 1 });
  mock.getSettings.mockResolvedValue({ soar_enabled: false, revision: 2 });
  mock.updateSettings.mockRejectedValueOnce(httpError(409, 'stale revision'));
  mock.updateSettings.mockResolvedValueOnce({
    soar_enabled: true,
    revision: 3,
  });
  renderPage();
  fireEvent.change(await openReason(), { target: { value: 'Go live' } });
  const button = screen.getByRole('button', { name: 'Enable SOAR' });
  await waitFor(() =>
    expect((button as HTMLButtonElement).disabled).toBe(false),
  );
  fireEvent.click(button);
  expect((await screen.findByRole('alert')).textContent).toMatch(
    /changed since you loaded it.*save again/,
  );
  await screen.findByText('disabled · revision 2');
  expect(mock.getSettings).toHaveBeenCalledTimes(2);
  // The reason is kept; the next save carries the refreshed revision.
  await waitFor(() =>
    expect((button as HTMLButtonElement).disabled).toBe(false),
  );
  fireEvent.click(button);
  await screen.findByText('SOAR enabled.');
  expect(mock.updateSettings).toHaveBeenLastCalledWith({
    soar_enabled: true,
    expected_revision: 2,
    reason: 'Go live',
  });
});

test('503 lock wait and 403 show retry and admin-only messages', async () => {
  mock.getSettings.mockResolvedValue({ soar_enabled: false, revision: 0 });
  mock.updateSettings.mockRejectedValueOnce(httpError(503, 'lock wait'));
  mock.updateSettings.mockRejectedValueOnce(httpError(403, 'forbidden'));
  renderPage();
  fireEvent.change(await openReason(), { target: { value: 'Enable' } });
  const button = screen.getByRole('button', { name: 'Enable SOAR' });
  await waitFor(() =>
    expect((button as HTMLButtonElement).disabled).toBe(false),
  );
  fireEvent.click(button);
  expect((await screen.findByRole('alert')).textContent).toMatch(
    /in progress\. Try again/,
  );
  await waitFor(() =>
    expect((button as HTMLButtonElement).disabled).toBe(false),
  );
  fireEvent.click(button);
  await waitFor(() =>
    expect(screen.getByRole('alert').textContent).toMatch(
      /Only a tenant admin/,
    ),
  );
});

test('reason stays hidden until requested and Cancel discards the inline draft', async () => {
  mock.getSettings.mockResolvedValue({ soar_enabled: false, revision: 1 });
  renderPage();
  await screen.findByText('disabled · revision 1');
  expect(screen.queryByLabelText('Reason')).toBeNull();
  fireEvent.change(await openReason(), { target: { value: 'Draft only' } });
  fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
  expect(screen.queryByLabelText('Reason')).toBeNull();
  expect(mock.updateSettings).not.toHaveBeenCalled();
  expect(await openReason()).toHaveProperty('value', '');
});

test('reason validation counts trimmed UTF-8 bytes at the 2048-byte boundary', async () => {
  mock.getSettings.mockResolvedValue({ soar_enabled: false, revision: 1 });
  renderPage();
  const reason = await openReason();
  const save = screen.getByRole('button', { name: 'Enable SOAR' });
  fireEvent.change(reason, { target: { value: 'é'.repeat(1025) } });
  expect(screen.getByText('2050 / 2048 bytes')).toBeTruthy();
  expect(save).toHaveProperty('disabled', true);
  fireEvent.change(reason, {
    target: { value: '  ' + 'é'.repeat(1024) + '  ' },
  });
  expect(screen.getByText('2048 / 2048 bytes')).toBeTruthy();
  expect(save).toHaveProperty('disabled', false);
});

test('a 409 that flips status cannot reverse the intended action on retry', async () => {
  mock.getSettings
    .mockResolvedValueOnce({ soar_enabled: false, revision: 1 })
    .mockResolvedValue({ soar_enabled: true, revision: 2 });
  mock.updateSettings.mockRejectedValueOnce(httpError(409, 'stale revision'));
  renderPage();
  fireEvent.change(await openReason(), { target: { value: 'Enable' } });
  fireEvent.click(screen.getByRole('button', { name: 'Enable SOAR' }));
  await screen.findByText('enabled · revision 2');
  expect(screen.getByRole('button', { name: 'Enable SOAR' })).toHaveProperty(
    'disabled',
    true,
  );
  expect(
    screen.getByText(/Another admin already made this change/),
  ).toBeTruthy();
  expect(mock.updateSettings).toHaveBeenCalledTimes(1);
});

test('audit history deep-links to the actual SOAR settings action', async () => {
  mock.getSettings.mockResolvedValue({ soar_enabled: false, revision: 0 });
  renderPage();
  expect(
    await screen.findByRole('link', { name: 'View audit history' }),
  ).toHaveProperty(
    'href',
    'http://localhost:3000/settings/audit?action=soar.settings.updated',
  );
});
