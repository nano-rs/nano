// SPDX-License-Identifier: AGPL-3.0-or-later
import { expect, it } from 'vitest';
import { fixedTimeRange, resolveRunTimeRange } from './search-run-scope';
import { toApiTimeRange } from '@/lib/time-range';

const preset = { type: 'preset' as const, preset: 'Last 30 days' };

it('NAN-3299: a run reuses the bounds it resolved while the picker holds the same range', () => {
  const range = { start: '2026-10-01T00:00:00.000Z', end: '2026-10-31T00:00:00.000Z' };
  const scope = { timeRange: preset, range };
  expect(resolveRunTimeRange(scope, preset)).toBe(range);
  expect(resolveRunTimeRange(scope, { ...preset })).toBe(range);
  // A different pick (or no run yet) resolves fresh.
  const other = { type: 'preset' as const, preset: 'Last 7 days' };
  expect(resolveRunTimeRange(scope, other)).not.toBe(range);
  expect(resolveRunTimeRange(null, preset).end).toBeTruthy();
});

it('NAN-3299: the URL carries exactly the bounds the run read', () => {
  const range = toApiTimeRange(preset);
  const fixed = fixedTimeRange(range);
  expect(fixed.type).toBe('custom');
  expect(toApiTimeRange(fixed)).toEqual(range);
});
