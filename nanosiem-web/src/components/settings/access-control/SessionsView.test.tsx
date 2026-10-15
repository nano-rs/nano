// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
/** NAN-3250: the access-control Sessions tab flows in the app scroller with a sticky column header. */
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import type { SessionInfo } from '@/lib/api';
import { SessionsView } from './SessionsView';

const now = new Date().toISOString();
const sessions: SessionInfo[] = [
  { id: 's1', user_id: 'u1', ip_address: '10.0.0.7', user_agent: 'Mozilla/5.0 (X11; Linux) Chrome/130', created_at: now, last_used_at: now, expires_at: now, is_current: true },
];

vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }));
vi.mock('@/contexts/AuthContext', () => ({ useAuth: () => ({ hasPermission: () => true }) }));
vi.mock('@/lib/api', () => ({
  api: {
    listAllSessions: () => Promise.resolve({ sessions, total: sessions.length }),
    listUsers: () => Promise.resolve({ users: [{ id: 'u1', name: 'Ana Analyst', email: 'ana@example.test' }], total: 1 }),
    terminateSession: vi.fn(),
  },
}));

afterEach(() => cleanup());

it('flows in the app scroller: no min-h-0 column or inner scroll box; the column header is sticky', async () => {
  render(<SessionsView />);
  const view = screen.getByTestId('sessions-view');
  expect(view.className).not.toMatch(/(^|\s)min-h-0(\s|$)/);
  const list = screen.getByTestId('sessions-list');
  expect(list.className).not.toMatch(/(^|\s)(min-h-0|flex-1|overflow-auto|overflow-y-auto)(\s|$)/);
  expect(screen.getByTestId('sessions-column-header').className).toMatch(/(^|\s)sticky(\s|$)/);
  await waitFor(() => expect(within(list).getByText('10.0.0.7')).toBeTruthy());
});
