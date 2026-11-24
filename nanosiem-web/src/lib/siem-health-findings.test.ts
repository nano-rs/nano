// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from 'vitest';
import { isSuppressibleFinding } from './siem-health-findings';

describe('isSuppressibleFinding (NAN-5738)', () => {
  it('the SOAR pack verification finding can never be suppressed', () => {
    expect(isSuppressibleFinding('SOAR installed packs failed signed catalog verification')).toBe(false);
    expect(isSuppressibleFinding('  soar installed packs failed   signed catalog verification ')).toBe(false);
  });
  it('other findings stay suppressible', () => {
    expect(isSuppressibleFinding('Fix src_ip extraction for windows_sysmon (7.7% fill rate)')).toBe(true);
  });
});
