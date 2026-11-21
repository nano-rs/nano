// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
/**
 * NAN-5707: no Disable / Delete on your own account (the server refuses both
 * with `cannot_modify_self`).
 * NAN-5708: each drawer action is gated on the permission its endpoint
 * checks: Edit / Unlock / Disable / Enable on `users:edit`, Delete on
 * `users:delete`. A `users:view`-only viewer gets no actions at all.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import type { UserDetail } from '@/lib/api';

vi.mock('@/contexts/AuthContext', () => ({ useAuth: () => ({ hasPermission: () => true, user: null }) }));
vi.mock('@/hooks/use-tier', () => ({ useTierContext: () => ({}) }));

import { UserDrawer } from './UsersView';
import { userDrawerActions } from './user-drawer-actions';

afterEach(cleanup);

function user(overrides: Partial<UserDetail> = {}): UserDetail {
  return {
    id: 'user_01other',
    email: 'other@example.com',
    name: 'Other User',
    status: 'active',
    groups: [],
    created_at: '2026-11-01T00:00:00Z',
    updated_at: '2026-11-01T00:00:00Z',
    ...overrides,
  };
}

const noop = () => {};

function drawer(target: UserDetail, opts: { me?: string; canEdit?: boolean; canDelete?: boolean } = {}) {
  render(
    <UserDrawer
      user={target}
      currentUserId={opts.me ?? 'user_01me'}
      canEdit={opts.canEdit ?? true}
      canDelete={opts.canDelete ?? true}
      onClose={noop}
      onEdit={noop}
      onDisable={noop}
      onEnable={noop}
      onUnlock={noop}
      onDelete={noop}
    />,
  );
  return (name: string) => screen.queryByRole('button', { name });
}

describe('user drawer actions (NAN-5707 / NAN-5708)', () => {
  it('an admin on another active user gets Edit, Disable and Delete', () => {
    const btn = drawer(user());
    expect(btn('Edit')).toBeTruthy();
    expect(btn('Disable')).toBeTruthy();
    expect(btn('Delete')).toBeTruthy();
  });

  it('your own account offers no Disable or Delete', () => {
    const btn = drawer(user({ id: 'user_01me' }), { me: 'user_01me' });
    expect(btn('Edit')).toBeTruthy();
    expect(btn('Disable')).toBeNull();
    expect(btn('Delete')).toBeNull();
  });

  it('a users:view-only viewer sees no action buttons', () => {
    for (const status of ['active', 'locked', 'disabled'] as const) {
      const btn = drawer(user({ status }), { canEdit: false, canDelete: false });
      for (const name of ['Edit', 'Disable', 'Enable', 'Unlock', 'Delete']) {
        expect(btn(name), `${name} on ${status}`).toBeNull();
      }
      cleanup();
    }
  });

  it('users:edit without users:delete hides only Delete', () => {
    const btn = drawer(user(), { canDelete: false });
    expect(btn('Edit')).toBeTruthy();
    expect(btn('Disable')).toBeTruthy();
    expect(btn('Delete')).toBeNull();
  });

  it('users:delete without users:edit offers only Delete', () => {
    const btn = drawer(user(), { canEdit: false });
    expect(btn('Edit')).toBeNull();
    expect(btn('Disable')).toBeNull();
    expect(btn('Delete')).toBeTruthy();
  });

  it('maps status to Unlock / Enable under users:edit', () => {
    const base = { isSelf: false, canEdit: true, canDelete: true };
    expect(userDrawerActions({ ...base, status: 'locked' })).toMatchObject({ unlock: true, disable: false, enable: false });
    expect(userDrawerActions({ ...base, status: 'disabled' })).toMatchObject({ enable: true, disable: false, unlock: false });
    // Enabling yourself is not a lockout (and a disabled user has no session).
    expect(userDrawerActions({ ...base, isSelf: true, status: 'disabled' }).enable).toBe(true);
  });

  it('never treats a missing current user id as self', () => {
    const btn = drawer(user({ id: '' }), { me: '' });
    expect(btn('Disable')).toBeTruthy();
  });
});
