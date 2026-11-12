// SPDX-License-Identifier: AGPL-3.0-or-later

import type { Alert } from '@/lib/api/types';

/**
 * NAN-5314: human label for an alert's assignee — the server-resolved name,
 * else the raw `assigned_to` (a legacy free-text assignee or a deleted user).
 * Never render `assigned_to` directly: it is a user typeid.
 */
export function alertAssigneeLabel(
  alert: Pick<Alert, 'assigned_to' | 'assignee_name'>,
): string | undefined {
  return alert.assignee_name || alert.assigned_to || undefined;
}
