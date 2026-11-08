// SPDX-License-Identifier: AGPL-3.0-or-later
/** NAN-4903: exact nPL literals for pivots (mirrors Rust npl_quoted_literal). */
import { describe, expect, it } from 'vitest';
import { nplExactEquals, nplLiteral } from './npl-quote';

describe('nplLiteral', () => {
  it('uses double quotes by default', () => {
    expect(nplLiteral('abc')).toEqual({ literal: '"abc"', lossy: false });
  });
  it('switches to single quotes to preserve a double quote', () => {
    expect(nplLiteral('say "hi"')).toEqual({ literal: `'say "hi"'`, lossy: false });
  });
  it('doubles backslashes and drops newlines', () => {
    expect(nplLiteral('\\\\srv\\s\nx').literal).toBe('"\\\\\\\\srv\\\\sx"');
  });
  it('flags a value with both quote kinds as lossy', () => {
    expect(nplLiteral(`it's "x"`)).toEqual({ literal: `"it's x"`, lossy: true });
  });
});

describe('nplExactEquals', () => {
  it.each([
    ['*', 'f IN ("*")'],
    ['a?b', 'f IN ("a?b")'],
    ['https://e.com/p?q=1&r=*', 'f IN ("https://e.com/p?q=1&r=*")'],
    ['plain', 'f="plain"'],
    ['C:\\x\\*', 'f IN ("C:\\\\x\\\\*")'],
  ])('%s', (value, expected) => {
    expect(nplExactEquals('f', value)).toBe(expected);
  });
});
