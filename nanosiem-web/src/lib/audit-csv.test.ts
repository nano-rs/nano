// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict';
import test from 'node:test';
import { auditCsvCell } from './audit-csv.ts';

test('audit export preserves quotes, commas and embedded record separators in one cell', () => {
  assert.equal(auditCsvCell('user "one", resource\r\nnext line'), '"user ""one"", resource\r\nnext line"');
  assert.equal(auditCsvCell('2026-09-09T18:00:00Z'), '"2026-09-09T18:00:00Z"');
});

test('untrusted audit values cannot start spreadsheet formulas', () => {
  for (const value of ['=1+1', '+1+1', '-1+1', '@SUM(1)', '  =1+1', '\t=1+1', '\r=1+1', '\n=1+1']) {
    assert.ok(auditCsvCell(value).startsWith('"\''));
  }
});
