// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
import type { ArtifactDetailCoverage } from '@/lib/api/types';
import { coverageSpan, detailCoverageLabel, detailCoverageTitle, isPartialCoverage } from './detailCoverage';

const base: ArtifactDetailCoverage = {
  complete: false, approximate: false, refining: false,
  scanned_start: '2026-10-13T14:15:00Z', scanned_end: '2026-10-13T15:00:00Z',
  window_start: '2026-09-13T15:00:00Z', window_end: '2026-10-13T15:00:00Z',
};

describe('detail coverage disclosure (NAN-3766)', () => {
  it('rounds the counted span down so it never overstates coverage', () => {
    expect(coverageSpan(45 * 60_000)).toBe('45m');
    expect(coverageSpan(30_000)).toBe('1m');
    expect(coverageSpan(6 * 3_600_000 + 59 * 60_000)).toBe('6h');
    expect(coverageSpan(52 * 3_600_000)).toBe('2d 4h');
    expect(coverageSpan(72 * 3_600_000)).toBe('3d');
  });

  it('labels partial, approximate and refining answers and omits exact ones', () => {
    expect(detailCoverageLabel(undefined, '30d')).toBeNull();
    expect(detailCoverageLabel({ ...base, complete: true }, '30d')).toBeNull();
    expect(detailCoverageLabel(base, '30d')).toBe('partial · last 45m of 30d');
    expect(detailCoverageLabel({ ...base, refining: true }, '30d')).toBe('partial · last 45m of 30d · refining…');
    expect(detailCoverageLabel({ ...base, approximate: true }, '30d')).toBe('partial · last 45m of 30d · approx');
    expect(detailCoverageLabel({ ...base, complete: true, approximate: true }, '30d')).toBe('approximate');
    expect(isPartialCoverage({ ...base, complete: true })).toBe(false);
  });

  it('explains the counted range in the title', () => {
    const title = detailCoverageTitle(base, '30d');
    expect(title).toContain('2026-10-13T14:15:00Z – 2026-10-13T15:00:00Z');
    expect(title).toContain('the newest 45m of this 30d window');
    expect(title).toContain('Search events for exact counts');
  });
});
