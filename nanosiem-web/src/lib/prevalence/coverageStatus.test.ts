// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from 'vitest';
import type { PrevalenceProductState } from '@/lib/api/types';
import { prevalenceStatusLabel, shouldPollPrevalence } from './coverageStatus';

const base: PrevalenceProductState = {
  state: 'ready',
  warming: false,
  stale: false,
  partial: false,
  covered_since: '2026-10-01T00:00:00Z',
  refreshed_at: null,
  ingest_head: '2026-11-03T12:00:00Z',
  window_start: '2026-11-02T12:00:00Z',
};

describe('prevalence coverage status', () => {
  it('is silent when ready or absent', () => {
    expect(prevalenceStatusLabel(base)).toBeNull();
    expect(prevalenceStatusLabel(undefined)).toBeNull();
    expect(shouldPollPrevalence(base)).toBe(false);
  });

  it('distinguishes warming from a definitive empty result', () => {
    const empty = { ...base, state: 'warming' as const, warming: true, covered_since: null, retry_after_s: 600 };
    expect(prevalenceStatusLabel(empty)).toContain('no prevalence yet for at least one artifact kind');
    expect(prevalenceStatusLabel(empty)).toContain('10 min');
    const young = { ...base, state: 'warming' as const, warming: true, covered_since: '2026-11-01T08:00:00Z' };
    expect(prevalenceStatusLabel(young)).toContain('2026-11-01 08:00 UTC');
    expect(shouldPollPrevalence(young)).toBe(true);
  });

  // NAN-5285 (v2.0.13 Helm retest): a fresh install's 30-day Rarity window
  // warms for 30 days, not "about 10 min"; the label must say until when.
  it('says when a young install covers the whole window', () => {
    const now = Date.parse('2026-11-11T12:00:00Z');
    const thirtyDays = {
      ...base,
      state: 'warming' as const,
      warming: true,
      retry_after_s: 600,
      covered_since: '2026-11-10T09:00:00Z',
      window_start: '2026-10-12T12:00:00Z',
    };
    const label = prevalenceStatusLabel(thirtyDays, now)!;
    expect(label).toContain('2026-11-10 09:00 UTC');
    expect(label).toContain('fully covered from about 2026-12-10 09:00 UTC');
    expect(label).toContain('unknown, not rare');
    expect(label).not.toContain('next refresh');
  });

  it('labels stale snapshots and partial coverage', () => {
    expect(prevalenceStatusLabel({ ...base, state: 'stale', stale: true, age_s: 1800 })).toContain('30 min old');
    expect(prevalenceStatusLabel({ ...base, state: 'partial', partial: true })).toContain('Partial coverage');
    expect(shouldPollPrevalence({ ...base, state: 'partial', partial: true })).toBe(false);
  });

  it('warming wins over stale', () => {
    expect(prevalenceStatusLabel({ ...base, state: 'warming', warming: true, stale: true })).toContain('Warming up');
  });
});
