// SPDX-License-Identifier: AGPL-3.0-or-later

import type { Alert } from '@/lib/api/types';

/** NAN-5774: a user typeid (`user_…`) or a bare UUID names a user account. */
const USER_REF = /^(?:user_[0-9a-z]{26}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i;

/**
 * NAN-5314: human label for an alert's assignee: the server-resolved name
 * ("deleted user" once the account is gone, NAN-5774), else a legacy
 * free-text assignee as is. A user id the server could not name is never
 * shown raw: it reads "unknown user".
 */
export function alertAssigneeLabel(
  alert: Pick<Alert, 'assigned_to' | 'assignee_name'>,
): string | undefined {
  if (alert.assignee_name) return alert.assignee_name;
  const raw = alert.assigned_to?.trim();
  if (!raw) return undefined;
  return USER_REF.test(raw) ? 'unknown user' : raw;
}

/**
 * NAN-5774: the assign picker's value. Only an id among the listed (active)
 * users is selectable; a deleted current assignee yields '' so it is never
 * preselected, shown raw or re-submitted.
 */
export function pickableAssignee(users: ReadonlyArray<{ id: string }>, assignTo: string): string {
  return users.some((u) => u.id === assignTo) ? assignTo : '';
}
