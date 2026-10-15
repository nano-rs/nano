// SPDX-License-Identifier: AGPL-3.0-or-later
/** NAN-3226: internal DNS suffix helpers. */
import { describe, expect, it } from 'vitest';
import {
  BUILTIN_INTERNAL_SUFFIXES,
  buildInternalDomainsPreviewQuery,
  effectiveInternalSuffixes,
  isInternalName,
  isPublicTldWarning,
  publicSuffixWarningText,
  REFUSED_PUBLIC_TLDS,
  refusedSuffixMessage,
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
    'ünïcode',
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

describe('isPublicTldWarning', () => {
  it('flags single-label public TLDs only', () => {
    expect(isPublicTldWarning('cloud')).toBe(true);
    expect(isPublicTldWarning('.PROD')).toBe(true);
    expect(isPublicTldWarning('corp.example.cloud')).toBe(false);
    expect(isPublicTldWarning('corp')).toBe(false);
    expect(isPublicTldWarning('bad name')).toBe(false);
  });

  it('never warns on a refused suffix (it is refused instead)', () => {
    for (const tld of REFUSED_PUBLIC_TLDS) expect(isPublicTldWarning(tld)).toBe(false);
  });
});

describe('refusedSuffixMessage (NAN-3230)', () => {
  it.each(['com', 'NET', '.io', 'app', 'dev', 'co', 'biz', 'info'])('refuses high-volume TLD %j', (raw) => {
    expect(refusedSuffixMessage(raw)).toMatch(/is a high-volume public TLD/);
  });
  it.each(['uk', 'de', 'au'])('refuses bare ccTLD %j', (raw) => {
    expect(refusedSuffixMessage(raw)).toMatch(/is a country-code TLD/);
  });
  it.each(['co.uk', 'com.au', 'ne.jp'])('refuses registry second level %j', (raw) => {
    expect(refusedSuffixMessage(raw)).toMatch(/is a public registry suffix/);
  });
  it.each(['cloud', 'prod', 'corp.example.com', 'example.co.uk', 'mycorp-internal', 'bad name'])(
    'allows %j',
    (raw) => {
      expect(refusedSuffixMessage(raw)).toBeNull();
    },
  );
  it('names the narrower alternative', () => {
    expect(refusedSuffixMessage('com')).toMatch(/such as corp\.example\.com\.$/);
  });
});

describe('publicSuffixWarningText', () => {
  it('spells out the blinding effect', () => {
    expect(publicSuffixWarningText('cloud')).toBe(
      'Domains under .cloud will no longer get threat-intel enrichment or domain rarity, including attacker-registered ones like evil.cloud. Prefer a narrower suffix such as corp.example.cloud.',
    );
  });
});

describe('buildInternalDomainsPreviewQuery', () => {
  it('builds a UDM query', () => {
    expect(buildInternalDomainsPreviewQuery(['prod'], 'udm')).toBe(
      'dest_host="*.prod" OR dest_host="prod" | stats dc(dest_host) as names',
    );
  });

  it('builds an OCSF query across suffixes and drops invalid ones', () => {
    expect(buildInternalDomainsPreviewQuery(['prod', 'Nano.Cloud', 'bad name'], 'ocsf')).toBe(
      'dst_endpoint.hostname="*.prod" OR dst_endpoint.hostname="prod" OR ' +
        'dst_endpoint.hostname="*.nano.cloud" OR dst_endpoint.hostname="nano.cloud" ' +
        '| stats dc(dst_endpoint.hostname) as names',
    );
  });

  it('returns null with no valid suffix', () => {
    expect(buildInternalDomainsPreviewQuery([], 'udm')).toBeNull();
    expect(buildInternalDomainsPreviewQuery(['a b'], 'udm')).toBeNull();
  });
});
