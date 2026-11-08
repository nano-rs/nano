// SPDX-License-Identifier: AGPL-3.0-or-later
import type { AuditLogQuery } from './api/types';

/** Server filters that a settings audit-history deep link may carry. */
export const AUDIT_URL_FILTER_KEYS = ['action', 'resource_type', 'source'] as const;
type AuditUrlFilterKey = (typeof AUDIT_URL_FILTER_KEYS)[number];

const MAX_FILTER_LENGTH = 128;

/** Only supported server filters survive a settings audit-history deep link. */
export function auditFiltersFromSearch(params: URLSearchParams): AuditLogQuery {
  const result: AuditLogQuery = { limit: 50, offset: 0 };
  for (const key of AUDIT_URL_FILTER_KEYS) {
    const value = params.get(key);
    if (value && value.length <= MAX_FILTER_LENGTH) result[key] = value;
  }
  return result;
}

/**
 * Write the deep-linkable filters back into the URL so the current view can be
 * shared. Other parameters (e.g. a hosting page's `tab`) are kept; cleared
 * filters are removed.
 */
export function auditFiltersToSearch(current: URLSearchParams, filters: AuditLogQuery): URLSearchParams {
  const next = new URLSearchParams(current);
  for (const key of AUDIT_URL_FILTER_KEYS) {
    const value = filters[key as AuditUrlFilterKey];
    if (value && value.length <= MAX_FILTER_LENGTH) next.set(key, value);
    else next.delete(key);
  }
  return next;
}

/** Whether two queries carry the same deep-linkable filters. */
export function sameAuditUrlFilters(a: AuditLogQuery, b: AuditLogQuery): boolean {
  return AUDIT_URL_FILTER_KEYS.every((key) => (a[key] || undefined) === (b[key] || undefined));
}
