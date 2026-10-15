// SPDX-License-Identifier: AGPL-3.0-or-later

import type { AuditLogEntry } from '@/lib/api/types';

/**
 * Audit actions that record routine, successful access rather than a change:
 * every automation-key request (`apikey_authenticated`) and session refresh.
 * They stay in the audit log (Settings → Audit shows them) but never fill the
 * "recent changes" / activity feeds. Failures of the same actions are kept:
 * a failed authentication is security-relevant.
 */
export const ROUTINE_AUDIT_ACTIONS: ReadonlySet<string> = new Set([
  'apikey_authenticated',
  'auth_session_refreshed',
]);

/** Rows fetched per feed so that a burst of routine rows cannot hide changes. */
export const RECENT_CHANGES_FETCH_LIMIT = 200;

export function isRoutineAuditEntry(entry: Pick<AuditLogEntry, 'action' | 'success'>): boolean {
  return entry.success !== false && ROUTINE_AUDIT_ACTIONS.has((entry.action || '').toLowerCase());
}

/** The first `limit` meaningful entries, newest first (input order kept). */
export function meaningfulAuditEntries(entries: AuditLogEntry[], limit: number): AuditLogEntry[] {
  return entries.filter((entry) => !isRoutineAuditEntry(entry)).slice(0, Math.max(0, limit));
}
