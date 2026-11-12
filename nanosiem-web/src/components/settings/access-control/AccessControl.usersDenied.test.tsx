// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
// NAN-5307: a role with roles:view / groups:view but not users:view must still
// see the role list, and the group member table must say why it is empty.
import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';

const perms = vi.hoisted(() => ({ value: new Set<string>() }));
const role = vi.hoisted(() => ({
  id: 'role_1', name: 'Analyst', description: 'SOC analyst', is_system: false,
  permissions: ['search:view'], created_at: '2026-11-11T00:00:00Z', updated_at: '2026-11-11T00:00:00Z',
}));
const group = vi.hoisted(() => ({
  id: 'group_1', name: 'Everyone', description: null, is_system: true, member_count: 7,
  roles: [{ id: 'role_1', name: 'Analyst' }],
  created_at: '2026-11-11T00:00:00Z', updated_at: '2026-11-11T00:00:00Z',
}));
const forbidden = vi.hoisted(() => Object.assign(new Error('Forbidden'), { status: 403 }));
const apiMock = vi.hoisted(() => ({
  listRoles: vi.fn(),
  listPermissions: vi.fn(),
  listGroups: vi.fn(),
  listUsers: vi.fn(),
}));
vi.mock('@/lib/api', () => ({ api: apiMock }));
vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({ hasPermission: (p: string) => perms.value.has(p) }),
}));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }));
vi.mock('@/enterprise/hooks/use-scim-group-sources', () => ({ useScimGroupSources: () => new Map() }));

import { RolesView } from './RolesView';
import { GroupsView, MEMBERS_NEED_USERS_VIEW } from './GroupsView';

beforeEach(() => {
  apiMock.listRoles.mockResolvedValue({ roles: [role] });
  apiMock.listPermissions.mockResolvedValue([]);
  apiMock.listGroups.mockResolvedValue({ groups: [group] });
  apiMock.listUsers.mockRejectedValue(forbidden);
});
afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

test('roles render without users:view, and /api/users is never called', async () => {
  perms.value = new Set(['roles:view', 'groups:view']);
  render(<RolesView />);
  expect((await screen.findAllByText('Analyst')).length).toBeGreaterThan(0);
  expect(screen.queryByText(/No roles yet/)).toBeNull();
  expect(apiMock.listUsers).not.toHaveBeenCalled();
});

test('roles still render when /api/users is refused despite users:view', async () => {
  perms.value = new Set(['roles:view', 'users:view']);
  render(<RolesView />);
  expect((await screen.findAllByText('Analyst')).length).toBeGreaterThan(0);
  expect(screen.queryByText(/No roles yet/)).toBeNull();
});

test('group members say users:view is needed instead of "No members yet"', async () => {
  perms.value = new Set(['groups:view', 'roles:view']);
  render(<GroupsView />);
  expect(await screen.findByText(MEMBERS_NEED_USERS_VIEW)).toBeTruthy();
  expect(screen.queryByText('No members yet.')).toBeNull();
  expect(apiMock.listUsers).not.toHaveBeenCalled();
});

test('a refused /api/users with users:view also explains the empty member list', async () => {
  perms.value = new Set(['groups:view', 'roles:view', 'users:view']);
  render(<GroupsView />);
  expect(await screen.findByText(MEMBERS_NEED_USERS_VIEW)).toBeTruthy();
  expect(screen.queryByText('No members yet.')).toBeNull();
});
