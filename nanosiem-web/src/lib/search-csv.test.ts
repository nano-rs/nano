// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import test from 'node:test';
import { searchCsvCell } from './search-csv.ts';

test('remote lookup fields and headers cannot become spreadsheet formulas', () => {
  for (const payload of ['=1+1', '+cmd', '-cmd', '@SUM(A1)', '  =1+1', '\t=1+1', '\r=1+1', '\n=1+1']) {
    assert.ok(searchCsvCell(payload).replace(/^"/u, '').startsWith("'"), payload);
  }
  assert.equal(searchCsvCell('a,"b"'), '"a,""b"""');
  assert.equal(searchCsvCell('ordinary'), 'ordinary');
});
