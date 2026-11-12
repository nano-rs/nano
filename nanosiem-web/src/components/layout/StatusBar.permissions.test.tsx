// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
// NAN-5325: shell chrome mounts for every role. It must not request what the
// role is refused (each refusal is a 403 and an audited auth_denied row), and
// must not claim "audit log healthy" when it read nothing.
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, expect, test, vi } from 'vitest';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

const perms = vi.hoisted(() => ({ value: new Set<string>() }));
const apiMock = vi.hoisted(() => ({
  getSiemHealthLatest: vi.fn().mockResolvedValue({ overall_status: 'healthy', status: 'healthy' }),
  getIngestionHistory: vi.fn().mockResolvedValue([]),
  getLicenseStatus: vi.fn(),
}));
vi.mock('@/lib/api', () => ({ api: apiMock }));
vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({ hasPermission: (p: string) => perms.value.has(p) }),
}));
vi.mock('@/components/layout/AppBreadcrumbs', () => ({ useCurrentPageTitle: () => 'Search' }));
vi.mock('@/hooks/use-capabilities', () => ({ useCapabilities: () => ({ edition: 'open', capabilities: {} }) }));

import { StatusBar } from './StatusBar';
import { SettingsStatusBar } from './settings/SettingsStatusBar';

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

test('a role without settings:system / log_sources:view sends neither read', async () => {
  perms.value = new Set(['search:view']);
  render(<MemoryRouter><StatusBar /></MemoryRouter>);
  await new Promise(r => setTimeout(r, 0));
  expect(apiMock.getSiemHealthLatest).not.toHaveBeenCalled();
  expect(apiMock.getIngestionHistory).not.toHaveBeenCalled();
});

test('each read is sent once the role holds its permission', async () => {
  perms.value = new Set(['settings:system', 'log_sources:view']);
  render(<MemoryRouter><StatusBar /></MemoryRouter>);
  await waitFor(() => expect(apiMock.getSiemHealthLatest).toHaveBeenCalled());
  expect(apiMock.getIngestionHistory).toHaveBeenCalledWith(1);
});

test('settings status bar makes no health claim without settings:system', async () => {
  perms.value = new Set(['settings:view']);
  render(<QueryClientProvider client={new QueryClient()}><SettingsStatusBar /></QueryClientProvider>);
  await new Promise(r => setTimeout(r, 0));
  expect(apiMock.getSiemHealthLatest).not.toHaveBeenCalled();
  expect(screen.queryByText(/audit log healthy/)).toBeNull();
});
