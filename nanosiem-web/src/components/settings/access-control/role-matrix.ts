// SPDX-License-Identifier: AGPL-3.0-or-later

import type { PermissionInfo } from '@/lib/api';
import { categoryDisplayName } from '@/lib/permissions';

export const CANONICAL_ACTIONS = ['view', 'create', 'edit', 'delete'] as const;
export type CanonicalAction = (typeof CANONICAL_ACTIONS)[number];

export interface MatrixRow {
  resource: string;
  /** Display label for the resource (e.g. "Detection Rules", "pivt"). */
  label: string;
  category: string;
  actions: Map<string, PermissionInfo>;
  specialAction?: { id: string; label: string; permission: PermissionInfo };
}

/**
 * Project flat `resource:action` permissions onto a Resource × action grid.
 *
 * NAN-5326: the row label used to be the first-seen permission's name minus
 * its last word, so rows were named after one of their actions ("Acknowledge"
 * for alerts, "Chat with" for the pivt row). The label now comes from the
 * resource key through the shared category display map, which also maps the
 * legacy `melod` key to "pivt".
 */
export function buildMatrix(permissions: PermissionInfo[]): MatrixRow[] {
  const byResource = new Map<string, MatrixRow>();
  for (const p of permissions) {
    const [resource, action] = p.id.split(':');
    if (!resource || !action) continue;
    let row = byResource.get(resource);
    if (!row) {
      row = {
        resource,
        label: categoryDisplayName(resource),
        category: p.category || 'other',
        actions: new Map(),
      };
      byResource.set(resource, row);
    }
    row.actions.set(action, p);
    if (!CANONICAL_ACTIONS.includes(action as CanonicalAction) && !row.specialAction) {
      row.specialAction = {
        id: action,
        label: action.charAt(0).toUpperCase() + action.slice(1),
        permission: p,
      };
    }
  }
  return Array.from(byResource.values()).sort((a, b) => {
    const cat = a.category.localeCompare(b.category);
    return cat !== 0 ? cat : a.resource.localeCompare(b.resource);
  });
}
