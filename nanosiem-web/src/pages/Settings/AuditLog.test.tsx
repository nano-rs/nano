// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { afterEach, expect, test, vi } from 'vitest';
import { auditFiltersFromSearch, auditFiltersToSearch } from '@/lib/audit-filters';

const mock = vi.hoisted(() => ({
  queryAuditLogs: vi.fn().mockResolvedValue({ logs: [], total: 0 }),
  exportAuditLogs: vi.fn(),
}));
vi.mock('@/lib/api', () => ({ api: mock }));
vi.mock('@/hooks/use-mobile', () => ({ useIsMobile: () => false }));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }));
import { AuditLogContent } from './AuditLog';
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.clearAllMocks();
});

function LocationProbe() {
  const location = useLocation();
  return <div data-testid="location">{location.pathname + location.search}</div>;
}

test.each(['soar_settings_updated', 'sso_sign_in_denied'])(
  'settings audit link applies the %s server filter',
  async (action) => {
    render(
      <MemoryRouter initialEntries={['/settings/audit?action=' + action]}>
        <AuditLogContent />
      </MemoryRouter>,
    );
    await waitFor(() =>
      expect(mock.queryAuditLogs).toHaveBeenCalledWith({
        action,
        limit: 50,
        offset: 0,
      }),
    );
  },
);

test('a deep link keeps unrelated params and does not rewrite itself', async () => {
  render(
    <MemoryRouter initialEntries={['/settings/audit?tab=audit&source=apikey']}>
      <AuditLogContent />
      <LocationProbe />
    </MemoryRouter>,
  );
  await waitFor(() =>
    expect(mock.queryAuditLogs).toHaveBeenCalledWith({ source: 'apikey', limit: 50, offset: 0 }),
  );
  expect(screen.getByTestId('location').textContent).toBe('/settings/audit?tab=audit&source=apikey');
});

test('API-key rows name the key and its owner', async () => {
  mock.queryAuditLogs.mockResolvedValueOnce({
    logs: [
      {
        id: 'a1', timestamp: '2026-11-03T10:00:00Z', user_name: 'alice', api_key_id: 'apikey_1',
        api_key_name: 'ci-bot', action: 'rule_created', source: 'detection', success: true,
      },
    ],
    total: 1,
  });
  render(
    <MemoryRouter initialEntries={['/settings/audit']}>
      <AuditLogContent />
    </MemoryRouter>,
  );
  expect(await screen.findByText('alice via key ci-bot')).toBeTruthy();
});

test('deep links accept supported filters, bounded and without paging or unsupported query data', () => {
  expect(
    auditFiltersFromSearch(
      new URLSearchParams(
        'action=inputlookup_allowlist_updated&source=search&resource_type=inputlookup&limit=999999&sql=ignored',
      ),
    ),
  ).toEqual({
    action: 'inputlookup_allowlist_updated',
    source: 'search',
    resource_type: 'inputlookup',
    limit: 50,
    offset: 0,
  });
  expect(
    auditFiltersFromSearch(new URLSearchParams({ action: 'x'.repeat(129) })),
  ).toEqual({ limit: 50, offset: 0 });
});

test('filters round-trip through the URL', () => {
  const filters = { action: 'rule_created', source: 'detection', limit: 50, offset: 100 };
  const params = auditFiltersToSearch(new URLSearchParams('tab=audit&resource_type=old'), filters);
  expect(params.toString()).toBe('tab=audit&action=rule_created&source=detection');
  expect(auditFiltersFromSearch(params)).toEqual({ action: 'rule_created', source: 'detection', limit: 50, offset: 0 });
});

test('Export all calls the bounded server export and shows progress', async () => {
  let finish!: (value: { blob: Blob; filename: string }) => void;
  mock.exportAuditLogs.mockReturnValueOnce(new Promise((resolve) => { finish = resolve; }));
  const createObjectURL = vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:audit');
  const revokeObjectURL = vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => undefined);
  const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined);

  render(
    <MemoryRouter initialEntries={['/settings/audit?action=rule_created&source=detection']}>
      <AuditLogContent />
    </MemoryRouter>,
  );
  const button = await screen.findByRole('button', { name: 'Export all' });
  fireEvent.click(button);

  expect((await screen.findByRole('status')).textContent).toContain('Exporting up to 100,000 matching rows');
  expect((screen.getByRole('button', { name: 'Exporting…' }) as HTMLButtonElement).disabled).toBe(true);
  expect(mock.exportAuditLogs).toHaveBeenCalledWith({
    action: 'rule_created',
    source: 'detection',
    limit: 100_000,
    format: 'csv',
  });

  await act(async () => finish({ blob: new Blob(['safe csv']), filename: 'audit_logs.csv' }));
  await waitFor(() => expect((screen.getByRole('button', { name: 'Export all' }) as HTMLButtonElement).disabled).toBe(false));
  expect(createObjectURL).toHaveBeenCalledOnce();
  expect(click).toHaveBeenCalledOnce();
  expect(revokeObjectURL).toHaveBeenCalledWith('blob:audit');
});

test('Export all is disabled while the local free-text search narrows the table', async () => {
  render(
    <MemoryRouter initialEntries={['/settings/audit?action=rule_created']}>
      <AuditLogContent />
    </MemoryRouter>,
  );

  const search = await screen.findByPlaceholderText('Search logs…');
  const button = await screen.findByRole('button', { name: 'Export all' }) as HTMLButtonElement;
  fireEvent.change(search, { target: { value: 'alice via key' } });

  expect(button.disabled).toBe(true);
  expect(screen.getByTestId('audit-export-all-search-reason').textContent)
    .toBe('Clear the search to export all rows matching the filters');
  fireEvent.click(button);
  expect(mock.exportAuditLogs).not.toHaveBeenCalled();

  fireEvent.change(search, { target: { value: '   ' } });
  expect(button.disabled).toBe(false);
  expect(screen.queryByTestId('audit-export-all-search-reason')).toBeNull();
});
