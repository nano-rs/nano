// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
import type { AuditLogEntry } from '@/lib/api/types';
import { auditActorLabel, isRoutineAuditEntry, meaningfulAuditEntries } from './audit-feed';

function entry(id: string, action: string, success = true): AuditLogEntry {
  return { id, timestamp: '2026-09-29T11:00:00Z', action, success } as AuditLogEntry;
}

describe('audit feed filtering', () => {
  it('drops routine successful key and session authentications', () => {
    expect(isRoutineAuditEntry(entry('1', 'apikey_authenticated'))).toBe(true);
    expect(isRoutineAuditEntry(entry('2', 'auth_session_refreshed'))).toBe(true);
    expect(isRoutineAuditEntry(entry('3', 'token_refresh'))).toBe(true);
    expect(isRoutineAuditEntry(entry('4', 'rule_created'))).toBe(false);
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
      entry('c', 'token_refresh'),
      entry('d', 'auth_denied', false),
      entry('e', 'webhook_updated'),
    ];
    expect(meaningfulAuditEntries(rows, 2).map((r) => r.id)).toEqual(['b', 'd']);
    expect(meaningfulAuditEntries(rows, 10).map((r) => r.id)).toEqual(['b', 'd', 'e']);
    expect(meaningfulAuditEntries([entry('x', 'apikey_authenticated')], 6)).toEqual([]);
  });
});

describe('audit actor label', () => {
  it('names the key and its owner for an API-key action', () => {
    expect(auditActorLabel({ user_name: 'alice', api_key_name: 'ci-bot' })).toBe('alice via key ci-bot');
    expect(auditActorLabel({ api_key_name: 'orphan' })).toBe('API key orphan');
    expect(auditActorLabel({ user_id: 'user_1', api_key_id: 'key_1' })).toBe('user_1 via key key_1');
  });

  it('falls back to the user, then system', () => {
    expect(auditActorLabel({ user_name: 'bob' })).toBe('bob');
    expect(auditActorLabel({})).toBe('system');
  });
});
