import { describe, expect, it } from 'vitest';

import { classifyIndicator, extractIndicators, extractWithStats, refang } from './indicator';

/**
 * Extraction is the front door of the bulk lookup. If it misses indicators, the
 * analyst is told a report is clean when it isn't — so the cases that matter are
 * the messy ones real reports actually contain.
 */

describe('refang', () => {
  it('undoes the conventions reports use to make indicators unclickable', () => {
    expect(refang('evil[.]com')).toBe('evil.com');
    expect(refang('evil(.)com')).toBe('evil.com');
    expect(refang('evil[dot]com')).toBe('evil.com');
    expect(refang('hxxps://evil.com')).toBe('https://evil.com');
    expect(refang('hxxp://evil.com')).toBe('http://evil.com');
    expect(refang('1.2.3[.]4')).toBe('1.2.3.4');
    expect(refang('admin[@]evil.com')).toBe('admin@evil.com');
  });
});

describe('extractIndicators', () => {
  it('pulls every indicator out of a realistic, defanged advisory', () => {
    const advisory = `
      Threat Report — APT-EXAMPLE

      The actor staged payloads on hxxps://cdn-update[.]example[.]net/p.bin and
      beaconed to 203.0.113.77 (and, later, 198[.]51[.]100[.]23:8443).

      Observed hashes:
        - d41d8cd98f00b204e9800998ecf8427e (dropper)
        - da39a3ee5e6b4b0d3255bfef95601890afd80709
        - 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08

      Contact: abuse@example.org. Report: vendor-report.pdf
    `;

    const values = extractIndicators(advisory).map((indicator) => indicator.value);

    // The URL reduces to its host — that is what the log data holds.
    expect(values).toContain('cdn-update.example.net');
    expect(values).toContain('203.0.113.77');
    // Defanged AND carrying a port.
    expect(values).toContain('198.51.100.23');
    expect(values).toContain('d41d8cd98f00b204e9800998ecf8427e');
    expect(values).toContain('da39a3ee5e6b4b0d3255bfef95601890afd80709');
    expect(values).toContain('9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08');

    // A filename is not a domain, however domain-shaped it looks.
    expect(values).not.toContain('vendor-report.pdf');
    // Nor is the report's own prose.
    expect(values).not.toContain('p.bin');
  });

  it('dedupes and counts the repeats', () => {
    // The same indicator, fanged and defanged, is ONE indicator.
    const { indicators, duplicates } = extractWithStats(
      'evil.com and evil[.]com and hxxps://evil.com/path — plus 8.8.8.8'
    );
    expect(indicators.map((indicator) => indicator.value)).toEqual(['evil.com', '8.8.8.8']);
    expect(duplicates).toBe(2);
  });

  it('preserves the order the analyst pasted', () => {
    const values = extractIndicators('9.9.9.9, evil.com, 1.1.1.1').map((i) => i.value);
    expect(values).toEqual(['9.9.9.9', 'evil.com', '1.1.1.1']);
  });

  it('strips a port but keeps an IPv6 address whole', () => {
    expect(extractIndicators('10.0.0.5:443').map((i) => i.value)).toEqual(['10.0.0.5']);
    expect(extractIndicators('[2001:db8::1]:8443').map((i) => i.value)).toEqual(['2001:db8::1']);
    expect(extractIndicators('2001:db8::1').map((i) => i.value)).toEqual(['2001:db8::1']);
  });

  it('drops trailing prose punctuation', () => {
    expect(extractIndicators('Beaconed to evil.com, then 8.8.8.8.').map((i) => i.value)).toEqual([
      'evil.com',
      '8.8.8.8',
    ]);
  });

  it('finds nothing in text that has nothing', () => {
    expect(extractIndicators('The attacker moved laterally over SMB.')).toEqual([]);
    expect(extractIndicators('')).toEqual([]);
  });

  it('does not mistake a MAC address for an IPv6 address', () => {
    // The classifier's job, exercised through the extractor it now feeds.
    expect(classifyIndicator('00:1a:2b:3c:4d:5e')).toBeNull();
  });
});
