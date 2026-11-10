// SPDX-License-Identifier: AGPL-3.0-or-later
/// <reference types="node" />

import assert from 'node:assert/strict';
import test from 'node:test';

import { nplQuotedBody, nplQuoted, nplFieldEquals, nplRegexBody } from './npl-quote.ts';

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

// --- NAN-5159: `/…/` regex literal bodies (tree pivot `root=/…/`) -----------

// Mirror of `parse_pattern_value` in
// nanosiem-core/src/query/parser/commands_enrichment.rs: a backslash escapes the
// next char, the first unescaped `/` closes the literal. Returns the body as the
// server hands it to the regex engine, plus whatever the parser would treat as
// further pipeline.
function parseNplRegexLiteral(emitted: string): { body: string; trailing: string } {
  assert.equal(emitted[0], '/', 'emitted literal must open with a slash');
  let escaped = false;
  for (let i = 1; i < emitted.length; i++) {
    const c = emitted[i];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (c === '\\') escaped = true;
    else if (c === '/') return { body: emitted.slice(1, i), trailing: emitted.slice(i + 1) };
  }
  assert.fail(`regex literal ${JSON.stringify(emitted)} never closes`);
}

/** The value must stay inside one `/…/` literal: nothing left over for the
 * parser to read as more pipeline. */
function assertRegexContained(raw: string) {
  const { body, trailing } = parseNplRegexLiteral(`/${nplRegexBody(raw)}/`);
  assert.equal(trailing, '', `input ${JSON.stringify(raw)} escaped its regex literal`);
  return body;
}

/** For values free of other regex metacharacters, the body must also match the
 * raw value literally (JS regex agrees with Rust `regex` on `\/` and `\\`). The
 * root filter is a regex by design, so `|`, `.` etc. keep regex meaning. */
function assertRegexRoundTrip(raw: string) {
  const body = assertRegexContained(raw);
  const flat = raw.replace(/[\r\n]/g, '');
  assert.ok(new RegExp(`^${body}$`).test(flat), `body ${body} must match ${JSON.stringify(flat)}`);
}

test('nplRegexBody escapes `/` so the value cannot close the literal', () => {
  assert.equal(nplRegexBody('a/b | head 1/x'), 'a\\/b | head 1\\/x');
  assertRegexRoundTrip('/usr/bin/curl');
  assertRegexContained('x/ | stats count by user | where count>0 | eval y=/');
});

test('nplRegexBody doubles backslashes so a trailing `\\` cannot escape the close', () => {
  assert.equal(nplRegexBody('C:\\Windows\\'), 'C:\\\\Windows\\\\');
  assertRegexRoundTrip('C:\\Windows\\');
  assertRegexRoundTrip('\\\\fileserver\\share');
  // A value pre-escaping its own slash must not pair up with ours.
  assertRegexContained('a\\/ | head 1');
  assertRegexRoundTrip('a\\/b');
});

test('nplRegexBody strips newlines and keeps pipes and quotes inert', () => {
  assert.equal(nplRegexBody('a\r\nb'), 'ab');
  assertRegexContained('line1\n| head 1');
  assertRegexContained('cmd|powershell "x"');
});

test('nplRegexBody leaves ordinary process / web names untouched', () => {
  assert.equal(nplRegexBody('powershell'), 'powershell');
  assert.equal(nplRegexBody('nginx-worker'), 'nginx-worker');
});

test('regression: the double-quote body escaper does NOT contain a regex literal', () => {
  // Why the tree pivots had to stop using nplQuotedBody for `root=/…/`.
  const { trailing } = parseNplRegexLiteral(`/${nplQuotedBody('a/ | head 1')}/`);
  assert.notEqual(trailing, '');
});
