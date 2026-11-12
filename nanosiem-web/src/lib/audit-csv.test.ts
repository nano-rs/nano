// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
import type { AuditLogEntry } from './api/types';
import { auditCsv, auditCsvCell } from './audit-csv';

describe('audit CSV', () => {
  it('preserves quotes, commas and embedded record separators in one cell', () => {
    expect(auditCsvCell('user "one", resource\r\nnext line')).toBe('"user ""one"", resource\r\nnext line"');
    expect(auditCsvCell('2026-09-09T18:00:00Z')).toBe('"2026-09-09T18:00:00Z"');
  });

  it('untrusted audit values cannot start spreadsheet formulas', () => {
    for (const value of ['=1+1', '+1+1', '-1+1', '@SUM(1)', '  =1+1', '\t=1+1', '\r=1+1', '\n=1+1']) {
      expect(auditCsvCell(value).startsWith('"\'')).toBe(true);
    }
  });

  it('exports exactly the given rows with the key and owner, injection-safe', () => {
    const rows = [
      {
        id: '1', timestamp: '2026-11-03T10:00:00Z', user_name: 'alice', api_key_name: '=HYPERLINK("x")',
        source: 'detection', action: 'rule_created', resource_type: 'rule', resource_name: '@evil',
        ip_address: '10.0.0.1', success: true,
      },
      { id: '2', timestamp: '2026-11-03T09:00:00Z', action: 'logout', success: false },
    ] as AuditLogEntry[];
    const lines = auditCsv(rows).split('\n');
    expect(lines).toHaveLength(3);
    expect(lines[0]).toBe('"Timestamp","Actor","API Key","Source","Action","Resource Type","Resource Name","IP Address","Success","Details"');
    expect(lines[1]).toBe(
      '"2026-11-03T10:00:00Z","alice via key =HYPERLINK(""x"")","\'=HYPERLINK(""x"")","detection","rule_created","rule","\'@evil","10.0.0.1","Yes",""',
    );
    expect(lines[2]).toBe('"2026-11-03T09:00:00Z","system","","","logout","","","","No",""');
  });

  it('NAN-5324: keeps the event details as one JSON cell', () => {
    const rows = [
      { id: '1', timestamp: 't', action: 'apikey_created', success: true, details: { permissions: ['alerts:view', 'rules:view'] } },
    ] as AuditLogEntry[];
    const line = auditCsv(rows).split('\n')[1];
    expect(line.endsWith(',"{""permissions"":[""alerts:view"",""rules:view""]}"')).toBe(true);
  });
});
