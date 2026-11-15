// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
// NAN-5449: the event retention control on Settings -> Storage. It shows the
// real TTL and who set it, saves through PUT
// /api/settings/storage/clickhouse/retention, confirms before a reduction,
// validates the range, and is read-only without settings:retention.
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import type { ClickHouseStorageStats } from '@/lib/api';

const mock = vi.hoisted(() => ({
  api: { updateClickHouseRetention: vi.fn() },
  perms: new Set<string>(['settings:retention']),
  toast: vi.fn(),
}));
vi.mock('@/lib/api', () => ({ api: mock.api }));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: mock.toast }) }));
vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({ hasPermission: (p: string) => mock.perms.has(p) }),
}));
import { RetentionPanel } from './RetentionSettings';

const stats = (over: Partial<ClickHouseStorageStats> = {}): ClickHouseStorageStats => ({
  total_size_bytes: 1,
  total_size_pretty: '1 B',
  row_count: 1,
  partition_count: 1,
  parts_count: 1,
  oldest_log: null,
  newest_log: null,
  compression_ratio: 5,
  uncompressed_size_bytes: 5,
  ttl_days: 365,
  retention_source: null,
  deployment_retention_days: null,
  ...over,
});

beforeEach(() => {
  mock.perms = new Set(['settings:retention']);
  mock.api.updateClickHouseRetention.mockReset().mockResolvedValue({ success: true, retention_days: 0, message: '' });
});
afterEach(cleanup);

test('shows the real TTL and its source', () => {
  render(
    <RetentionPanel
      stats={stats({ ttl_days: 90, retention_source: 'deployment', deployment_retention_days: 90 })}
      diskDays={40}
      onSaved={vi.fn()}
    />,
  );
  expect(screen.getByTestId('retention-current').textContent).toBe('90 days');
  expect(screen.getByText(/set by deployment \(NANO_RETENTION_DAYS=90\)/)).toBeTruthy();
  expect(screen.getByText(/disk holds ~40 days/)).toBeTruthy();
});

test('raising retention saves without a confirmation', async () => {
  const onSaved = vi.fn();
  render(<RetentionPanel stats={stats({ ttl_days: 30 })} diskDays={null} onSaved={onSaved} />);
  fireEvent.change(screen.getByLabelText('Retention in days'), { target: { value: '90' } });
  fireEvent.click(screen.getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(mock.api.updateClickHouseRetention).toHaveBeenCalledWith(90));
  expect(onSaved).toHaveBeenCalledWith(90);
});

test('reducing retention asks first', async () => {
  render(<RetentionPanel stats={stats({ ttl_days: 365 })} diskDays={null} onSaved={vi.fn()} />);
  fireEvent.change(screen.getByLabelText('Retention in days'), { target: { value: '30' } });
  fireEvent.click(screen.getByRole('button', { name: 'Save' }));
  expect(mock.api.updateClickHouseRetention).not.toHaveBeenCalled();
  fireEvent.click(await screen.findByRole('button', { name: 'Reduce retention' }));
  await waitFor(() => expect(mock.api.updateClickHouseRetention).toHaveBeenCalledWith(30));
});

test('an unknown current retention always asks first', async () => {
  render(<RetentionPanel stats={stats({ ttl_days: null })} diskDays={null} onSaved={vi.fn()} />);
  expect(screen.getByTestId('retention-current').textContent).toBe('unknown');
  fireEvent.change(screen.getByLabelText('Retention in days'), { target: { value: '30' } });
  fireEvent.click(screen.getByRole('button', { name: 'Save' }));
  expect(mock.api.updateClickHouseRetention).not.toHaveBeenCalled();
  expect(await screen.findByText(/could not be read/)).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Reduce retention' }));
  await waitFor(() => expect(mock.api.updateClickHouseRetention).toHaveBeenCalledWith(30));
});

test('out-of-range values cannot be saved', () => {
  render(<RetentionPanel stats={stats()} diskDays={null} onSaved={vi.fn()} />);
  const input = screen.getByLabelText('Retention in days');
  for (const bad of ['0', '3651', '12.5', 'abc']) {
    fireEvent.change(input, { target: { value: bad } });
    expect((screen.getByRole('button', { name: 'Save' }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText(/whole number of days, 1-3650/)).toBeTruthy();
  }
  fireEvent.change(input, { target: { value: '3' } });
  expect(screen.getByText(/Under 7 days/)).toBeTruthy();
});

test('read-only without settings:retention', () => {
  mock.perms = new Set();
  render(<RetentionPanel stats={stats()} diskDays={null} onSaved={vi.fn()} />);
  expect(screen.queryByLabelText('Retention in days')).toBeNull();
  expect(screen.getByTestId('retention-current').textContent).toBe('365 days');
});
