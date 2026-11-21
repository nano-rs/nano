// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
/**
 * NAN-5713: Settings > Users must not call GET /api/groups (needs groups:view)
 * for a users:view-only viewer.
 * NAN-5707: the edit dialog keeps your own Admin-granting groups checked and
 * locked (the API refuses removing your own administrator access).
 */
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const perms = vi.hoisted(() => ({ value: new Set<string>() }));
const me = vi.hoisted(() => ({ value: { id: 'user_01me' } as { id: string } | null }));
const apiMock = vi.hoisted(() => ({
  listUsers: vi.fn(),
  listGroups: vi.fn(),
  updateUser: vi.fn(),
}));
vi.mock('@/lib/api', () => ({ api: apiMock }));
vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({ hasPermission: (p: string) => perms.value.has(p), user: me.value }),
}));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }));
vi.mock('@/hooks/use-tier', () => ({ useTierContext: () => ({ status: null, isEnforced: false }) }));

import { UsersView } from './UsersView';
import { EditUserDialog } from './EditUserDialog';

const adminGroup = {
  id: 'group_admins', name: 'Administrators', is_system: false, member_count: 1,
  roles: [{ id: 'role_admin', name: 'Admin', is_system: true }],
  created_at: '2026-11-01T00:00:00Z', updated_at: '2026-11-01T00:00:00Z',
};
const analysts = {
  id: 'group_analysts', name: 'Analysts', is_system: false, member_count: 1,
  roles: [{ id: 'role_ro', name: 'ReadOnly', is_system: true }],
  created_at: '2026-11-01T00:00:00Z', updated_at: '2026-11-01T00:00:00Z',
};
const user = (id: string) => ({
  id, email: `${id}@example.com`, name: id, status: 'active' as const,
  groups: [
    { id: adminGroup.id, name: adminGroup.name, is_system: false },
    { id: analysts.id, name: analysts.name, is_system: false },
  ],
  created_at: '2026-11-01T00:00:00Z', updated_at: '2026-11-01T00:00:00Z',
});

beforeEach(() => {
  apiMock.listUsers.mockResolvedValue({ users: [user('user_01other')], total: 1 });
  apiMock.listGroups.mockResolvedValue({ groups: [adminGroup, analysts], total: 2 });
});
afterEach(() => {
  cleanup();
  perms.value = new Set();
  vi.clearAllMocks();
});

describe('Settings > Users groups call (NAN-5713)', () => {
  it('does not list groups without groups:view', async () => {
    perms.value = new Set(['users:view']);
    render(<UsersView />);
    await waitFor(() => expect(apiMock.listUsers).toHaveBeenCalled());
    expect(apiMock.listGroups).not.toHaveBeenCalled();
  });

  it('lists groups with groups:view', async () => {
    perms.value = new Set(['users:view', 'groups:view']);
    render(<UsersView />);
    await waitFor(() => expect(apiMock.listGroups).toHaveBeenCalledTimes(1));
  });
});

describe('edit dialog on your own account (NAN-5707)', () => {
  const box = (name: string) => screen.getByRole('checkbox', { name });

  it('locks your own Admin-granting group, other groups stay editable', () => {
    render(
      <EditUserDialog open user={user('user_01me')} groups={[adminGroup, analysts]} onClose={() => {}} onUpdated={() => {}} />,
    );
    expect((box('Administrators') as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(box('Administrators'));
    expect(box('Administrators').getAttribute('aria-checked')).toBe('true');
    expect((box('Analysts') as HTMLButtonElement).disabled).toBe(false);
  });

  it("another user's Admin group is editable", () => {
    render(
      <EditUserDialog open user={user('user_01other')} groups={[adminGroup, analysts]} onClose={() => {}} onUpdated={() => {}} />,
    );
    expect((box('Administrators') as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(box('Administrators'));
    expect(box('Administrators').getAttribute('aria-checked')).toBe('false');
  });
});
