// SPDX-License-Identifier: AGPL-3.0-or-later

import type { AuditLogEntry } from '@/lib/api/types';

/**
 * Audit actions that record routine, successful access rather than a change:
 * automation-key authentications (`apikey_authenticated`) and session/token
 * refreshes (`auth_session_refreshed`, dedicated `token_refresh`). They stay in
 * the audit log (Settings → Audit shows them) but never fill the "recent
 * changes" / activity feeds. Failures of the same actions are kept: a failed
 * authentication is security-relevant (NAN-3031).
 */
export const ROUTINE_AUDIT_ACTIONS: ReadonlySet<string> = new Set([
  'apikey_authenticated',
  'auth_session_refreshed',
  'token_refresh',
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

/**
 * Who acted, as the audit trail shows it. An API-key action names the key
 * and its owner ("alice via key ci-bot"); `user_name` is the owning user
 * the server resolved for the key (NAN-3031).
 */
export function auditActorLabel(
  log: Pick<AuditLogEntry, 'user_name' | 'user_id' | 'api_key_name' | 'api_key_id'>,
): string {
  const owner = log.user_name || log.user_id;
  const key = log.api_key_name || log.api_key_id;
  if (key) return owner ? `${owner} via key ${key}` : `API key ${key}`;
  return owner || 'system';
}
