// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';

const group = vi.hoisted(() => ({
  id: 'group_1',
  name: 'SOC Admins',
  description: null,
  is_system: false,
  member_count: 1,
  roles: [{ id: 'role_1', name: 'Admin' }],
  created_at: '2026-11-11T00:00:00Z',
  updated_at: '2026-11-11T00:00:00Z',
}));
const sources = vi.hoisted(() => ({ value: new Map() }));
vi.mock('@/lib/api', () => ({
  api: {
    listGroups: vi.fn().mockResolvedValue({ groups: [group] }),
    listRoles: vi.fn().mockResolvedValue({ roles: [] }),
    listUsers: vi.fn().mockResolvedValue({ users: [] }),
  },
}));
vi.mock('@/contexts/AuthContext', () => ({ useAuth: () => ({ hasPermission: () => true }) }));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }));
vi.mock('@/enterprise/hooks/use-scim-group-sources', () => ({
  useScimGroupSources: () => sources.value,
}));

import { GroupsView } from './GroupsView';

beforeEach(() => {
  sources.value = new Map();
});
afterEach(cleanup);

test('groups with no SCIM source stay Local and show no SCIM banner', async () => {
  render(<GroupsView />);
  expect((await screen.findAllByText('Local')).length).toBeGreaterThan(0);
  expect(screen.queryByText('SCIM')).toBeNull();
  expect(screen.queryByText(/provisioned over SCIM/)).toBeNull();
});

test('a group fed by a SCIM-provisioned IdP group shows the pill and banner', async () => {
  sources.value = new Map([
    ['group_1', [{ group_id: 'group_1', provider_id: 'oidc_1', provider_name: 'Okta', idp_group: 'siem-admins' }]],
  ]);
  render(<GroupsView />);
  expect((await screen.findAllByText('SCIM')).length).toBe(2);
  expect(screen.getByText(/provisioned over SCIM from/)).toBeTruthy();
  expect(screen.getByText('siem-admins')).toBeTruthy();
});
