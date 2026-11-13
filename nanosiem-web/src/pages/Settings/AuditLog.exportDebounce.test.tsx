// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
// NAN-5333: "Export all" right after typing a search (inside the search
// debounce) must export the searched rows, never every row.
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

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

test('Export all clicked inside the search debounce still carries the search', async () => {
  mock.exportAuditLogs.mockResolvedValueOnce({ blob: new Blob(['x']), filename: 'a.csv' });
  vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:a');
  vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => undefined);
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined);
  render(
    <MemoryRouter initialEntries={['/settings/audit?action=apikey_created']}>
      <AuditLogContent />
    </MemoryRouter>,
  );
  fireEvent.change(await screen.findByPlaceholderText('Search logs…'), { target: { value: ' probe ' } });
  // No wait for the debounced refetch: click immediately.
  fireEvent.click(screen.getByRole('button', { name: 'Export all' }));
  await waitFor(() =>
    expect(mock.exportAuditLogs).toHaveBeenCalledWith({
      action: 'apikey_created',
      q: 'probe',
      limit: 100_000,
      format: 'csv',
    }),
  );
});
