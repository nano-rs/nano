// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import type { BackupStatusResponse } from '../lib/api/system-health';

const mock = vi.hoisted(() => ({
  status: null as BackupStatusResponse | null,
  permissions: ['settings:system'] as string[],
  calls: 0,
}));

vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({ hasPermission: (p: string) => mock.permissions.includes(p) }),
}));
vi.mock('../lib/api', async (importOriginal) => {
  const original = await importOriginal<typeof import('../lib/api')>();
  return {
    ...original,
    api: {
      systemHealth: { getBackupStatus: async () => { mock.calls += 1; return mock.status; } },
    },
  };
});

import { BackupStatusBanner } from './BackupStatusBanner';
import { BACKUP_BANNER_DISMISSED_KEY } from '../lib/backup-status';

const backup = (over: Partial<BackupStatusResponse> = {}): BackupStatusResponse => ({
  configured: true, enabled: true, enabled_since: '2026-11-01T00:00:00Z',
  last_attempt_at: '2026-11-09T02:00:00Z', last_outcome: 'failure',
  last_success_at: '2026-11-07T02:04:00Z', last_success_backup_id: 'nano-20261107T020000Z-ab12cd34-host',
  last_success_size_bytes: 12345, last_failure_at: '2026-11-09T02:00:00Z', last_failure_error: 'AccessDenied',
  consecutive_failures: 2, destination_kind: 's3', destination: 's3://bucket/nano', clickhouse_data: 'excluded',
  schedule: '02:00', keep: 7, next_run_at: '2026-11-10T02:00:00Z', updated_at: '2026-11-09T02:00:00Z',
  stale: true, stale_after_hours: 36, ...over,
});

function renderBanner() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter>
      <QueryClientProvider client={client}><BackupStatusBanner /></QueryClientProvider>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  mock.status = null; mock.permissions = ['settings:system']; mock.calls = 0;
  window.sessionStorage.clear();
});
afterEach(cleanup);

test('shows when stale for a settings:system holder, with the last success in mono', async () => {
  mock.status = backup();
  renderBanner();
  expect(await screen.findByText('No successful backup in 36 hours')).toBeTruthy();
  const last = screen.getByTestId('backup-banner-last-success');
  expect(last.textContent).toBe('Nov 7, 02:04 UTC');
  expect(last.className).toContain('font-mono');
  expect(screen.getByText('Automatic backups').getAttribute('href'))
    .toBe('https://nano.rs/docs/administration/backup#automatic-backups');
});

test('says never when no backup ever succeeded', async () => {
  mock.status = backup({ last_success_at: null });
  renderBanner();
  expect((await screen.findByTestId('backup-banner-last-success')).textContent).toBe('never');
});

test('hidden when not stale or not configured', async () => {
  mock.status = backup({ stale: false });
  renderBanner();
  await vi.waitFor(() => expect(mock.calls).toBe(1));
  expect(screen.queryByText(/No successful backup/)).toBeNull();
  cleanup();

  mock.status = backup({ configured: false, enabled: null, stale: false });
  renderBanner();
  await vi.waitFor(() => expect(mock.calls).toBe(2));
  expect(screen.queryByText(/No successful backup/)).toBeNull();
});

test('never polls or renders without settings:system', async () => {
  mock.status = backup();
  mock.permissions = [];
  renderBanner();
  await new Promise((r) => setTimeout(r, 20));
  expect(mock.calls).toBe(0);
  expect(screen.queryByText(/No successful backup/)).toBeNull();
});

test('dismissal lasts for the session only', async () => {
  mock.status = backup();
  const first = renderBanner();
  fireEvent.click(await screen.findByLabelText('Dismiss backup warning for this session'));
  expect(screen.queryByText(/No successful backup/)).toBeNull();
  expect(window.sessionStorage.getItem(BACKUP_BANNER_DISMISSED_KEY)).toBe('1');
  first.unmount();

  renderBanner();
  await new Promise((r) => setTimeout(r, 20));
  expect(screen.queryByText(/No successful backup/)).toBeNull();
  cleanup();

  window.sessionStorage.clear();
  renderBanner();
  expect(await screen.findByText('No successful backup in 36 hours')).toBeTruthy();
});
