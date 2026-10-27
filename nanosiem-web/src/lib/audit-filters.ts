// SPDX-License-Identifier: AGPL-3.0-or-later
import type { AuditLogQuery } from './api/types';

/** Only supported server filters survive a settings audit-history deep link. */
export function auditFiltersFromSearch(params: URLSearchParams): AuditLogQuery {
  const result: AuditLogQuery = { limit: 50, offset: 0 };
  for (const key of ['action', 'resource_type', 'source'] as const) {
    const value = params.get(key);
    if (value && value.length <= 128) result[key] = value;
  }
  return result;
}
