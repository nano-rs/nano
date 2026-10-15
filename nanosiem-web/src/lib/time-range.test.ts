// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  formatTimeWindow,
  formatTimeWindowLabel,
  presetShortLabel,
  readTimeRangeParams,
  toApiTimeRange,
  trailingWindowTitle,
  writeTimeRangeParams,
  TIME_RANGE_PRESETS,
  type TimeRangeValue,
} from './time-range';
import { urlTimeRange } from '@/pages/search-run-scope';

// NAN-3884: a relative pick keeps its relative label everywhere; the window it
// resolved to is secondary text in the viewer's timezone.

const NY = 'America/New_York';
const NOW = new Date('2026-10-15T14:02:00Z'); // 10:02 EDT

afterEach(() => vi.useRealTimers());

describe('presetShortLabel', () => {
  it('gives every windowed preset its compact label', () => {
    expect(presetShortLabel('Last 15 minutes')).toBe('15m');
    expect(presetShortLabel('Last hour')).toBe('1h');
    expect(presetShortLabel('Last 4 hours')).toBe('4h');
    expect(presetShortLabel('Last 24 hours')).toBe('24h');
    expect(presetShortLabel('Last 7 days')).toBe('7d');
    expect(presetShortLabel('Last 30 days')).toBe('30d');
    for (const category of TIME_RANGE_PRESETS) {
      for (const p of category.presets) expect(presetShortLabel(p.value)).toBe(p.short);
    }
  });

  it('passes an unknown preset through unchanged', () => {
    expect(presetShortLabel('Last 2 hours')).toBe('Last 2 hours');
  });
});

describe('formatTimeWindow', () => {
  it('renders start → end in the given timezone with its abbreviation', () => {
    expect(formatTimeWindow(
      { start: '2026-10-08T14:02:00Z', end: '2026-10-15T14:02:00Z' }, NY, NOW,
    )).toBe('Oct 8 10:02 → Oct 15 10:02 EDT');
  });

  it('uses 24h clock and shows years when the window crosses one', () => {
    expect(formatTimeWindow(
      { start: '2025-12-31T23:30:00Z', end: '2026-01-01T01:00:00Z' }, 'UTC', NOW,
    )).toBe('Dec 31, 2025 23:30 → Jan 1, 2026 01:00 UTC');
  });

  it('returns empty for unparseable bounds', () => {
    expect(formatTimeWindow({ start: 'nope', end: 'nope' }, NY, NOW)).toBe('');
  });
});

describe('formatTimeWindowLabel', () => {
  it('prefixes a preset with its relative label', () => {
    vi.useFakeTimers({ now: NOW });
    const value: TimeRangeValue = { type: 'preset', preset: 'Last 7 days' };
    expect(formatTimeWindowLabel(value, toApiTimeRange(value), NY, NOW))
      .toBe('7d · Oct 8 10:02 → Oct 15 10:02 EDT');
  });

  it('shows only the window for a fixed range', () => {
    const value: TimeRangeValue = { type: 'custom', start: new Date('2026-10-01T04:00:00Z'), end: new Date('2026-10-01T10:00:00Z') };
    expect(formatTimeWindowLabel(value, toApiTimeRange(value), NY, NOW)).toBe('Oct 1 00:00 → Oct 1 06:00 EDT');
  });
});

describe('trailingWindowTitle', () => {
  it('resolves a trailing duration back from now', () => {
    expect(trailingWindowTitle(24 * 3_600_000, NOW, NY)).toBe('Oct 14 10:02 → Oct 15 10:02 EDT');
  });
  it('has no window for all time', () => {
    expect(trailingWindowTitle(null, NOW, NY)).toBeUndefined();
  });
});

describe('URL round-trip', () => {
  it('keeps a relative pick relative', () => {
    const params = new URLSearchParams('q=foo&start=2026-01-01T00:00:00.000Z&end=2026-01-02T00:00:00.000Z');
    writeTimeRangeParams(params, { type: 'preset', preset: 'Last 7 days', refreshedAt: 123 });
    expect(params.get('time')).toBe('Last 7 days');
    expect(params.has('start')).toBe(false);
    expect(params.has('end')).toBe(false);
    expect(params.get('q')).toBe('foo');
    // Through a string, as a reload or a copied link would.
    const back = readTimeRangeParams(new URLSearchParams(params.toString()));
    expect(back).toEqual({ type: 'preset', preset: 'Last 7 days' });
  });

  it('re-resolves a relative pick on each read', () => {
    const params = new URLSearchParams();
    writeTimeRangeParams(params, { type: 'preset', preset: 'Last hour' });
    vi.useFakeTimers({ now: NOW });
    const first = toApiTimeRange(readTimeRangeParams(params)!);
    vi.setSystemTime(new Date(NOW.getTime() + 600_000));
    const second = toApiTimeRange(readTimeRangeParams(params)!);
    expect(Date.parse(second.end) - Date.parse(first.end)).toBe(600_000);
  });

  it('keeps a fixed range absolute', () => {
    const start = new Date('2026-10-01T04:00:00.000Z');
    const end = new Date('2026-10-01T10:00:00.000Z');
    const params = new URLSearchParams('time=Last+hour');
    writeTimeRangeParams(params, { type: 'custom', start, end });
    expect(params.has('time')).toBe(false);
    expect(params.get('start')).toBe(start.toISOString());
    expect(params.get('end')).toBe(end.toISOString());
    expect(readTimeRangeParams(new URLSearchParams(params.toString()))).toEqual({ type: 'custom', start, end });
  });

  it('reads nothing when the URL names no range', () => {
    expect(readTimeRangeParams(new URLSearchParams('q=foo'))).toBeNull();
  });

  it('a search run writes the relative pick, or the fixed bounds it resolved', () => {
    const range = { start: '2026-10-08T14:02:00.000Z', end: '2026-10-15T14:02:00.000Z' };
    expect(urlTimeRange({ type: 'preset', preset: 'Last 7 days', refreshedAt: 9 }, range))
      .toEqual({ type: 'preset', preset: 'Last 7 days' });
    expect(urlTimeRange({ type: 'custom', start: new Date(range.start), end: new Date(range.end) }, range))
      .toEqual({ type: 'custom', start: new Date(range.start), end: new Date(range.end) });
  });
});
