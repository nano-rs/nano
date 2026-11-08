// SPDX-License-Identifier: AGPL-3.0-or-later
/** NAN-3226: internal DNS suffix helpers. */
import { describe, expect, it } from 'vitest';
import {
  BUILTIN_INTERNAL_SUFFIXES,
  effectiveInternalSuffixes,
  isInternalName,
  normalizeSuffix,
} from './internal-domains';

describe('isInternalName', () => {
  it('matches on a label boundary', () => {
    expect(isInternalName('db1.prod', ['prod'])).toBe(true);
    expect(isInternalName('prod', ['prod'])).toBe(true);
    expect(isInternalName('DB1.PROD.', ['prod'])).toBe(true);
    expect(isInternalName('a.b.corp.example.com', ['corp.example.com'])).toBe(true);
    expect(isInternalName('myprod.com', ['prod'])).toBe(false);
    expect(isInternalName('db1.myprod', ['prod'])).toBe(false);
    expect(isInternalName('prod.example.com', ['prod'])).toBe(false);
    expect(isInternalName('example.com', ['corp.example.com'])).toBe(false);
  });

  it('unions tenant suffixes with the built-ins', () => {
    expect(isInternalName('ws-01.corp.local')).toBe(true);
    expect(isInternalName('1.0.168.192.in-addr.arpa', [])).toBe(true);
    expect(isInternalName('db1.prod')).toBe(false);
    expect(isInternalName('ws-01.corp.local', ['prod'])).toBe(true);
    expect(isInternalName('evil.example.com', ['prod'])).toBe(false);
    expect(isInternalName('', ['prod'])).toBe(false);
  });

  it('tolerates un-normalized tenant entries', () => {
    expect(isInternalName('db1.prod', ['PROD.'])).toBe(true);
  });
});

describe('normalizeSuffix', () => {
  it('trims, lowercases and strips wildcard / dots', () => {
    expect(normalizeSuffix('  Corp.Example.COM ')).toBe('corp.example.com');
    expect(normalizeSuffix('*.nano.cloud')).toBe('nano.cloud');
    expect(normalizeSuffix('.prod')).toBe('prod');
    expect(normalizeSuffix('prod.')).toBe('prod');
    expect(normalizeSuffix('_msdcs.corp')).toBe('_msdcs.corp');
  });

  it.each([
    '',
    '   ',
    '.',
    '*.',
    'a..b',
    '-prod',
    'prod-',
    'corp.-x',
    'bad name',
    'a/b',
    'x'.repeat(64),
    `${'a'.repeat(60)}.`.repeat(5),
    '10.0.0.1',
    'fe80::1',
    
  ])('rejects %j', (raw) => {
    expect(normalizeSuffix(raw)).toBeNull();
  });

  it('accepts a 63-char label', () => {
    expect(normalizeSuffix('x'.repeat(63))).toBe('x'.repeat(63));
  });
});

describe('effectiveInternalSuffixes', () => {
  it('keeps built-ins first and de-duplicates', () => {
    expect(effectiveInternalSuffixes(['Prod', 'corp', 'bad name'])).toEqual([
      ...BUILTIN_INTERNAL_SUFFIXES,
      'prod',
    ]);
  });
});

describe('IDNA equivalence (U-label vs A-label)', () => {
  it('matches a U-label name against an A-label suffix and the reverse', () => {
    expect(isInternalName('db.bücher.example', ['xn--bcher-kva.example'])).toBe(true);
    expect(isInternalName('DB.XN--BCHER-KVA.EXAMPLE', ['bücher.example'])).toBe(true);
    expect(isInternalName('db.bucher.example', ['bücher.example'])).toBe(false);
    expect(normalizeSuffix('*.Bücher.Example.')).toBe('xn--bcher-kva.example');
  });
});
