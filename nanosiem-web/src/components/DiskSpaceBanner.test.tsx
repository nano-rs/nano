// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import type { DiskAlertResponse } from '../lib/api/system-health';
import type { DiskVolumeHealth } from '../lib/api/siem-health';

const mock = vi.hoisted(() => ({
  alert: null as DiskAlertResponse | null,
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
    api: { systemHealth: { getDiskAlert: async () => { mock.calls += 1; return mock.alert; } } },
  };
});

import { DiskSpaceBanner, DiskUsageNotice } from './DiskSpaceBanner';
import { DISK_BANNER_SNOOZED_KEY, hoursText } from '../lib/disk-alert';

const disk = (over: Partial<DiskVolumeHealth> = {}): DiskVolumeHealth => ({
  component: 'clickhouse', name: 'default', total_bytes: 100, used_bytes: 96, free_bytes: 4,
  usage_fraction: 0.96, level: 'imminent', detail: '96.0% used',
  forecast: { growth_bytes_per_hour: 2, hours_to_full: 2, samples: 12, span_hours: 1, escalated: false },
  ...over,
});

const alertOf = (over: Partial<DiskAlertResponse> = {}): DiskAlertResponse => ({
  level: 'imminent', disks: [disk()], ingestion_paused: false, warn_fraction: 0.8,
  critical_fraction: 0.9, imminent_fraction: 0.95, runbook: 'docs/administration/disk-full-recovery.md',
  checked_at: '2026-11-14T00:00:00Z', ...over,
});

function renderWith(node: React.ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter>
      <QueryClientProvider client={client}>{node}</QueryClientProvider>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  mock.alert = null; mock.permissions = ['settings:system']; mock.calls = 0;
  window.localStorage.clear();
});
afterEach(cleanup);

test('imminent: red, not dismissible, with the forecast, what happens next and the runbook', async () => {
  mock.alert = alertOf();
  renderWith(<DiskSpaceBanner />);
  const banner = await screen.findByTestId('disk-banner');
  expect(banner.getAttribute('data-level')).toBe('imminent');
  expect(banner.getAttribute('role')).toBe('alert');
  expect(banner.className).toContain('bg-red-50');
  expect(screen.getByText('Disk almost full')).toBeTruthy();
  expect(screen.getByTestId('disk-banner-usage').textContent).toBe('96.0% used');
  expect(screen.getByTestId('disk-banner-forecast').textContent).toBe('about 2 hours until full');
  expect(screen.getByTestId('disk-banner-next').textContent).toContain('ingest will pause, and the oldest data will be dropped');
  expect(screen.getByText('Disk-full runbook').getAttribute('href')).toContain('disk-full-recovery');
  expect(screen.queryByLabelText(/Snooze disk warning/)).toBeNull();
});

test('imminent ignores an earlier snooze', async () => {
  window.localStorage.setItem(DISK_BANNER_SNOOZED_KEY, String(Date.now() + 3_600_000));
  mock.alert = alertOf();
  renderWith(<DiskSpaceBanner />);
  expect(await screen.findByTestId('disk-banner')).toBeTruthy();
});

test('a paused ingest is said plainly', async () => {
  mock.alert = alertOf({ ingestion_paused: true, ingestion_pause_source: 'disk_pressure' });
  renderWith(<DiskSpaceBanner />);
  const paused = await screen.findByTestId('disk-banner-paused');
  expect(paused.textContent).toContain('Ingestion is paused by disk pressure');
  expect(screen.queryByTestId('disk-banner-next')).toBeNull();
});

test('critical: amber (never red), snoozable for an hour', async () => {
  mock.alert = alertOf({
    level: 'critical',
    disks: [disk({ level: 'critical', usage_fraction: 0.6, forecast: { growth_bytes_per_hour: 2, hours_to_full: 20, samples: 30, span_hours: 6, escalated: true } })],
  });
  renderWith(<DiskSpaceBanner />);
  const banner = await screen.findByTestId('disk-banner');
  expect(banner.className).toContain('bg-amber-50');
  expect(banner.className).not.toContain('bg-red');
  expect(screen.getByText('Disk filling fast')).toBeTruthy();
  expect(screen.getByTestId('disk-banner-forecast').textContent).toBe('about 20 hours until full');
  fireEvent.click(screen.getByLabelText('Snooze disk warning for an hour'));
  expect(screen.queryByTestId('disk-banner')).toBeNull();
  const until = Number(window.localStorage.getItem(DISK_BANNER_SNOOZED_KEY));
  expect(until).toBeGreaterThan(Date.now() + 59 * 60_000);
});

test('the ClickHouse forecast counts to the ingest pause', async () => {
  mock.alert = alertOf({
    level: 'critical',
    disks: [disk({ level: 'critical', usage_fraction: 0.84, forecast: { growth_bytes_per_hour: 2, hours_to_full: 20, full_fraction: 0.92, samples: 30, span_hours: 6, escalated: true } })],
  });
  renderWith(<DiskSpaceBanner />);
  await screen.findByTestId('disk-banner');
  expect(screen.getByTestId('disk-banner-forecast').textContent).toBe('about 20 hours until ingestion pauses at 92%');
});

test('warning and ok show no banner; non-admins never ask', async () => {
  mock.alert = alertOf({ level: 'warning', disks: [disk({ level: 'warning', usage_fraction: 0.82 })] });
  renderWith(<DiskSpaceBanner />);
  await vi.waitFor(() => expect(mock.calls).toBe(1));
  expect(screen.queryByTestId('disk-banner')).toBeNull();
  cleanup();
  mock.permissions = ['alerts:view']; mock.calls = 0;
  renderWith(<DiskSpaceBanner />);
  await new Promise((r) => setTimeout(r, 20));
  expect(mock.calls).toBe(0);
});

test('the Storage notice lists every disk at 80 % or more with its forecast', async () => {
  mock.alert = alertOf({
    level: 'warning',
    disks: [
      disk({ level: 'warning', usage_fraction: 0.82, forecast: { growth_bytes_per_hour: 1, hours_to_full: 72, samples: 30, span_hours: 6, escalated: false } }),
      disk({ component: 'postgres', name: 'database', level: 'warning', usage_fraction: 0.81, forecast: undefined }),
    ],
  });
  renderWith(<DiskUsageNotice />);
  const notice = await screen.findByTestId('disk-usage-notice');
  expect(notice.textContent).toContain('2 data disks are above 80%');
  expect(notice.textContent).toContain('ClickHouse disk default');
  expect(notice.textContent).toContain('full in about 3 days');
  expect(notice.textContent).toContain('PostgreSQL volume database');
});

test('hoursText matches the server wording', () => {
  expect(hoursText(0.25)).toBe('15 minutes');
  expect(hoursText(1)).toBe('1 hour');
  expect(hoursText(20)).toBe('20 hours');
  expect(hoursText(72)).toBe('3 days');
});
