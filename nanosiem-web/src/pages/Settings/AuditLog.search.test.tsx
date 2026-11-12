// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
// NAN-5308: the audit search box filters server-side (every matching row,
// not only the loaded page). NAN-5324: the Action filter lists every
// recorded action.
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, expect, test, vi } from 'vitest';

const mock = vi.hoisted(() => ({
  queryAuditLogs: vi.fn().mockResolvedValue({ logs: [], total: 0 }),
  exportAuditLogs: vi.fn(),
  getAuditActions: vi.fn().mockResolvedValue([]),
}));
vi.mock('@/lib/api', () => ({ api: mock }));
vi.mock('@/hooks/use-mobile', () => ({ useIsMobile: () => false }));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }));
import { AuditLogContent } from './AuditLog';
import { auditActionOptions } from '@/lib/audit-actions';

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

test('typing a search queries the server with q from offset 0', async () => {
  render(
    <MemoryRouter initialEntries={['/settings/audit?action=apikey_created']}>
      <AuditLogContent />
    </MemoryRouter>,
  );
  const search = await screen.findByPlaceholderText('Search logs…');
  fireEvent.change(search, { target: { value: '  pa-probe-key ' } });
  await waitFor(() =>
    expect(mock.queryAuditLogs).toHaveBeenLastCalledWith({
      action: 'apikey_created',
      q: 'pa-probe-key',
      limit: 50,
      offset: 0,
    }),
  );
  // The search box stays mounted across the refetch.
  expect(screen.getByPlaceholderText('Search logs…')).toBeTruthy();

  fireEvent.change(search, { target: { value: '' } });
  await waitFor(() =>
    expect(mock.queryAuditLogs).toHaveBeenLastCalledWith({ action: 'apikey_created', limit: 50, offset: 0 }),
  );
});

test('server matches render even when not on the first unfiltered page', async () => {
  mock.queryAuditLogs.mockImplementation(async (f: { q?: string }) =>
    f.q
      ? {
          logs: [{ id: 'x', timestamp: '2026-11-12T00:00:00Z', user_name: 'pa', action: 'apikey_created', source: 'apikey', resource_type: 'api_key', resource_name: 'pa-probe-key', success: true }],
          total: 12,
        }
      : { logs: [], total: 1078 },
  );
  render(
    <MemoryRouter initialEntries={['/settings/audit']}>
      <AuditLogContent />
    </MemoryRouter>,
  );
  fireEvent.change(await screen.findByPlaceholderText('Search logs…'), { target: { value: 'pa-probe-key' } });
  expect(await screen.findByText('pa-probe-key')).toBeTruthy();
  mock.queryAuditLogs.mockReset();
  mock.queryAuditLogs.mockResolvedValue({ logs: [], total: 0 });
});

test('Export all carries the search to the server export', async () => {
  mock.exportAuditLogs.mockResolvedValueOnce({ blob: new Blob(['x']), filename: 'a.csv' });
  vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:a');
  vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => undefined);
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined);
  render(
    <MemoryRouter initialEntries={['/settings/audit']}>
      <AuditLogContent />
    </MemoryRouter>,
  );
  fireEvent.change(await screen.findByPlaceholderText('Search logs…'), { target: { value: 'probe' } });
  await waitFor(() => expect(mock.queryAuditLogs).toHaveBeenLastCalledWith({ q: 'probe', limit: 50, offset: 0 }));
  const button = screen.getByRole('button', { name: 'Export all' }) as HTMLButtonElement;
  expect(button.disabled).toBe(false);
  fireEvent.click(button);
  await waitFor(() =>
    expect(mock.exportAuditLogs).toHaveBeenCalledWith({ q: 'probe', limit: 100_000, format: 'csv' }),
  );
});

test('Action options include every recorded action, labelled, plus the selected one', () => {
  const opts = auditActionOptions(['search_settings_updated', 'apikey_reset', 'login_success'], 'rule_promoted');
  const values = opts.map(o => o.value);
  expect(values[0]).toBe('__all__');
  for (const v of ['search_settings_updated', 'apikey_reset', 'rule_promoted', 'login_success', 'logout']) {
    expect(values).toContain(v);
  }
  expect(new Set(values).size).toBe(values.length);
  expect(opts.find(o => o.value === 'search_settings_updated')?.label).toBe('Search Settings Updated');
  expect(opts.find(o => o.value === 'login_success')?.label).toBe('Login Success');
});
