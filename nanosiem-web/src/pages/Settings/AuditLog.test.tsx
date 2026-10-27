// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
import { cleanup, render, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, expect, test, vi } from 'vitest';
import { auditFiltersFromSearch } from '@/lib/audit-filters';

const mock = vi.hoisted(() => ({
  queryAuditLogs: vi.fn().mockResolvedValue({ logs: [], total: 0 }),
}));
vi.mock('@/lib/api', () => ({ api: mock }));
vi.mock('@/hooks/use-mobile', () => ({ useIsMobile: () => false }));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }));
import { AuditLogContent } from './AuditLog';
afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

test.each(['soar.settings.updated', 'inputlookup_allowlist_updated'])(
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
