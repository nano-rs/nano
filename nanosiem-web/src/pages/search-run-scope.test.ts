// SPDX-License-Identifier: AGPL-3.0-or-later
import { expect, it } from 'vitest';
import { DUPLICATE_RUN_WINDOW_MS, fixedTimeRange, repeatsRun, searchRunStart } from './search-run-scope';
import { toApiTimeRange } from '@/lib/time-range';

const at = Date.parse('2026-10-15T05:33:31.439Z');
const preset = { type: 'preset' as const, preset: 'Last 30 days' };

it('NAN-3883: the same search moments later repeats the run, a relative pick and its URL bounds alike', () => {
  const first = searchRunStart('* | stats count by source_type', 'piped', 'logs', 100, preset, at);
  expect(repeatsRun(first, searchRunStart('* | stats count by source_type ', 'piped', 'logs', 100, preset, at + 200))).toBe(true);
  // The URL-written absolute bounds of that run are the same search.
  const urlRange = fixedTimeRange(toApiTimeRange(preset));
  expect(repeatsRun(first, searchRunStart('* | stats count by source_type', 'piped', 'logs', 100, urlRange, at + 300))).toBe(true);
});

it('NAN-3883: another query, dataset, filter, window, or a later re-run is a new run', () => {
  const first = searchRunStart('* | stats count by source_type', 'piped', 'logs', 100, preset, at);
  const again = (query: string, dataset = 'logs', prevalence = 100, range = preset, when = at + 100) =>
    repeatsRun(first, searchRunStart(query, 'piped', dataset, prevalence, range, when));
  expect(again('* | stats count by metadata.log_source')).toBe(false);
  expect(again('* | stats count by source_type', 'risk')).toBe(false);
  expect(again('* | stats count by source_type', 'logs', 10)).toBe(false);
  expect(again('* | stats count by source_type', 'logs', 100, { type: 'preset', preset: 'Last 7 days' })).toBe(false);
  expect(again('* | stats count by source_type', 'logs', 100, preset, at + DUPLICATE_RUN_WINDOW_MS)).toBe(false);
  expect(repeatsRun(null, first)).toBe(false);
});
