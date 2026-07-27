// SPDX-License-Identifier: AGPL-3.0-or-later
/// <reference types="node" />

import assert from 'node:assert/strict';
import test from 'node:test';

import { nplQuotedBody, nplQuoted, nplFieldEquals } from './npl-quote.ts';

// The parser's contract, mirrored here so these tests assert against the real
// grammar rather than against the helper's own implementation:
//   double_quoted_string = delimited('"', take_while(|c| c != '"'), '"')
//                          then s.replace("\\\\", "\\")
// See nanosiem-core/src/query/parser/values.rs::double_quoted_string.
function parseNplDoubleQuoted(emitted: string): { value: string; trailing: string } {
  assert.equal(emitted[0], '"', 'emitted literal must open with a quote');
  const close = emitted.indexOf('"', 1);
  assert.notEqual(close, -1, 'emitted literal must close');
  return {
    value: emitted.slice(1, close).replace(/\\\\/g, '\\'),
    trailing: emitted.slice(close + 1),
  };
}

/** The whole point: whatever we emit must parse back to a single literal. */
function assertRoundTrip(raw: string, expected: string) {
  const { value, trailing } = parseNplDoubleQuoted(nplQuoted(raw));
  assert.equal(value, expected, `value mismatch for input ${JSON.stringify(raw)}`);
  assert.equal(trailing, '', `input ${JSON.stringify(raw)} escaped its literal`);
}

test('plain values are untouched', () => {
  assert.equal(nplQuotedBody('web-server-01'), 'web-server-01');
  assertRoundTrip('web-server-01', 'web-server-01');
  assertRoundTrip('10.0.0.9', '10.0.0.9');
});

test('NAN-2184: an embedded double quote cannot break out of the literal', () => {
  // The old `.replace(/"/g, '\\"')` emitted src_host="a\" OR src_ip=\"10.0.0.9"
  // which the real parser rejects with `Unexpected token '='`.
  const hostile = 'a" OR src_ip=10.0.0.9';
  assert.equal(nplQuotedBody(hostile), 'a OR src_ip=10.0.0.9');
  assertRoundTrip(hostile, 'a OR src_ip=10.0.0.9');
});

test('NAN-2184: a value made only of quotes collapses to an empty literal', () => {
  assert.equal(nplQuoted('"""'), '""');
  assertRoundTrip('"""', '');
});

test('NAN-1157: a trailing backslash stays inside the literal', () => {
  // `"C:\Windows\System32\"` must not swallow the close quote.
  assertRoundTrip('C:\\Windows\\System32\\', 'C:\\Windows\\System32\\');
});

test('NAN-2184: UNC double-backslash survives the parser\u2019s \\\\ collapse', () => {
  // Without escaping, `"\\fileserver\share"` parses back as `\fileserver\share`
  // — one backslash silently lost. This is the defect CodeQL actually flagged.
  assertRoundTrip('\\\\fileserver\\share', '\\\\fileserver\\share');
  assert.equal(nplQuoted('\\\\fileserver\\share'), '"\\\\\\\\fileserver\\\\share"');
});

test('single backslashes round-trip (why the pre-existing sites looked clean)', () => {
  assertRoundTrip('C:\\Users\\dan', 'C:\\Users\\dan');
});

test('newlines are stripped so the query stays one line', () => {
  assert.equal(nplQuotedBody('a\nb\r\nc'), 'abc');
  assertRoundTrip('evil\n| head 1', 'evil| head 1');
});

test('inert characters are preserved for legitimate values', () => {
  // These cannot break out of a quoted literal, so stripping them would only
  // corrupt real data.
  assertRoundTrip('cmd|powershell', 'cmd|powershell');
  assertRoundTrip('(foo|bar)[1]`x`', '(foo|bar)[1]`x`');
});

test('backslash escaping happens before quote stripping', () => {
  // A value ending in `\` followed by a `"` must not let the stripped quote
  // leave a dangling escape that pairs with the next character.
  assertRoundTrip('trail\\"next', 'trail\\next');
});

test('nplFieldEquals composes field and quoted value', () => {
  assert.equal(nplFieldEquals('src_host', 'web-01'), 'src_host="web-01"');
  assert.equal(nplFieldEquals('src_host', 'a"b'), 'src_host="ab"');
});

test('unicode and empty input are handled', () => {
  assertRoundTrip('', '');
  assertRoundTrip('höst-über', 'höst-über');
  assertRoundTrip('日本語', '日本語');
});
