// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
// NAN-5235: a Search URL alone never grants an auto-run.
import { beforeEach, expect, it } from 'vitest';
import {
  SEARCH_AUTO_RUN_TTL_MS,
  consumeSearchAutoRun,
  grantSearchAutoRun,
  isSearchAutoRunGranted,
  resolveSearchAutoRun,
  withSearchAutoRun,
} from './search-auto-run';

beforeEach(() => localStorage.clear());

it('a grant is bound to its exact query', () => {
  const token = grantSearchAutoRun('error');
  expect(isSearchAutoRunGranted(token, 'error')).toBe(true);
  expect(isSearchAutoRunGranted(token, 'error | output x')).toBe(false);
});

it('legacy, forged and empty run values are never granted', () => {
  for (const value of ['true', '1', '', null, undefined, '00000000-0000-4000-8000-000000000000', '../x']) {
    expect(isSearchAutoRunGranted(value as string | null | undefined, 'error')).toBe(false);
  }
});

it('a grant is single-use', () => {
  const token = grantSearchAutoRun('error');
  consumeSearchAutoRun(token);
  expect(isSearchAutoRunGranted(token, 'error')).toBe(false);
});

it('a grant expires', () => {
  const now = 1_000_000;
  const token = grantSearchAutoRun('error', now);
  expect(isSearchAutoRunGranted(token, 'error', now + SEARCH_AUTO_RUN_TTL_MS - 1)).toBe(true);
  expect(isSearchAutoRunGranted(token, 'error', now + SEARCH_AUTO_RUN_TTL_MS)).toBe(false);
});

it('withSearchAutoRun grants the URL’s own query, in fragment and query-string form', () => {
  const frag = withSearchAutoRun(`/search#q=${encodeURIComponent('user="a"')}&time=Last+hour`);
  const fragParams = new URLSearchParams(frag.split('#')[1]);
  expect(fragParams.get('time')).toBe('Last hour');
  expect(isSearchAutoRunGranted(fragParams.get('run'), 'user="a"')).toBe(true);

  const qs = withSearchAutoRun('/search?q=error');
  expect(isSearchAutoRunGranted(new URLSearchParams(qs.split('?')[1]).get('run'), 'error')).toBe(true);
});

it('resolveSearchAutoRun swaps only the run=true intent marker', () => {
  const resolved = resolveSearchAutoRun('/search#q=error&run=true&ai=true');
  const params = new URLSearchParams(resolved.split('#')[1]);
  expect(params.get('run')).not.toBe('true');
  expect(isSearchAutoRunGranted(params.get('run'), 'error')).toBe(true);
  expect(params.get('ai')).toBe('true');
  expect(resolveSearchAutoRun('/alerts/1')).toBe('/alerts/1');
});
