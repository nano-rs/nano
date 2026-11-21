// SPDX-License-Identifier: AGPL-3.0-or-later

import type { UserDetail } from '@/lib/api';

export interface UserDrawerActions {
  edit: boolean;
  unlock: boolean;
  disable: boolean;
  enable: boolean;
  delete: boolean;
}

/**
 * Which drawer actions to offer (NAN-5707 / NAN-5708). Each one is gated on
 * the permission its endpoint checks: Edit, Unlock, Disable and Enable on
 * `users:edit` (PUT /api/users/{id}, POST /{id}/unlock|disable|enable), Delete
 * on `users:delete`. Disable and Delete are never offered on your own account;
 * the server refuses both (`cannot_modify_self`).
 */
export function userDrawerActions(opts: {
  status: UserDetail['status'];
  isSelf: boolean;
  canEdit: boolean;
  canDelete: boolean;
}): UserDrawerActions {
  const { status, isSelf, canEdit, canDelete } = opts;
  return {
    edit: canEdit,
    unlock: canEdit && status === 'locked',
    disable: canEdit && !isSelf && status === 'active',
    enable: canEdit && status === 'disabled',
    delete: canDelete && !isSelf,
  };
}
