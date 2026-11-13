// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
// NAN-5329: audit rows stay one line — the timestamp cell never wraps and the
// actor is not cut to 90px.
import { cleanup, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, expect, test, vi } from 'vitest';

const ACTOR = 'e2e-platform-admin-c25f98';
const mock = vi.hoisted(() => ({
  queryAuditLogs: vi.fn(),
  exportAuditLogs: vi.fn(),
  getAuditActions: vi.fn().mockResolvedValue([]),
}));
vi.mock('@/lib/api', () => ({ api: mock }));
vi.mock('@/hooks/use-mobile', () => ({ useIsMobile: () => false }));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }));
import { AuditLogContent } from './AuditLog';

afterEach(cleanup);

test('timestamp cell is nowrap and the actor keeps room', async () => {
  mock.queryAuditLogs.mockResolvedValue({
    logs: [{ id: 'x', timestamp: '2026-11-12T03:21:40Z', user_name: ACTOR, action: 'apikey_deleted', source: 'apikey', resource_type: 'api_key', resource_name: 'pa-probe-key', success: true }],
    total: 1,
  });
  render(
    <MemoryRouter initialEntries={['/settings/audit']}>
      <AuditLogContent />
    </MemoryRouter>,
  );
  const actor = await screen.findByTitle(ACTOR);
  expect(actor.className).not.toContain('max-w-[90px]');
  const row = actor.closest('tr')!;
  expect(row.querySelector('td')!.className).toContain('whitespace-nowrap');
});
