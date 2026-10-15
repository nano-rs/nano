// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
import type { AuditLogEntry } from '@/lib/api/types';
import { isRoutineAuditEntry, meaningfulAuditEntries } from './audit-feed';

function entry(id: string, action: string, success = true): AuditLogEntry {
  return { id, timestamp: '2026-09-29T11:00:00Z', action, success } as AuditLogEntry;
}

describe('audit feed filtering', () => {
  it('drops routine successful key and session authentications', () => {
    expect(isRoutineAuditEntry(entry('1', 'apikey_authenticated'))).toBe(true);
    expect(isRoutineAuditEntry(entry('2', 'auth_session_refreshed'))).toBe(true);
    expect(isRoutineAuditEntry(entry('3', 'rule_created'))).toBe(false);
  });

  it('keeps failures and security-relevant key events', () => {
    expect(isRoutineAuditEntry(entry('1', 'apikey_authenticated', false))).toBe(false);
    for (const action of ['apikey_rate_limited', 'apikey_created', 'apikey_revoked', 'auth_denied']) {
      expect(isRoutineAuditEntry(entry(action, action))).toBe(false);
    }
  });

  it('returns the newest meaningful entries up to the limit', () => {
    const rows = [
      entry('a', 'apikey_authenticated'),
      entry('b', 'rule_created'),
      entry('c', 'apikey_authenticated'),
      entry('d', 'auth_denied', false),
      entry('e', 'webhook_updated'),
    ];
    expect(meaningfulAuditEntries(rows, 2).map((r) => r.id)).toEqual(['b', 'd']);
    expect(meaningfulAuditEntries(rows, 10).map((r) => r.id)).toEqual(['b', 'd', 'e']);
    expect(meaningfulAuditEntries([entry('x', 'apikey_authenticated')], 6)).toEqual([]);
  });
});
