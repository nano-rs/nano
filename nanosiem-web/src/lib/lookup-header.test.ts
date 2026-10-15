// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
import { firstRowIsHeader, urlFirstRowIsHeader } from './lookup-header';

describe('lookup first-row toggle defaults', () => {
  it('defaults indicator lists to headerless and named columns to headers', () => {
    expect(firstRowIsHeader('1.0.164.165\n1.0.212.159')).toBe(false);
    expect(firstRowIsHeader('malware.example\nphishing.example')).toBe(false);
    expect(firstRowIsHeader('d41d8cd98f00b204e9800998ecf8427e\n900150983cd24fb0d6963f7d28e17f72')).toBe(false);
    expect(firstRowIsHeader('ip\n1.0.164.165')).toBe(true);
    expect(firstRowIsHeader('name,age\nAlice,30')).toBe(true);
    expect(urlFirstRowIsHeader('https://example.com/ips.txt?key=x')).toBe(false);
    expect(urlFirstRowIsHeader('https://example.com/indicators.csv')).toBe(true);
  });
});
