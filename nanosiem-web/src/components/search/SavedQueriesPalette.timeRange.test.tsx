// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { SavedQueriesPalette } from './SavedQueriesPalette';
import { savedSearchTimeRange, savedSearchTimeRangeValue } from '@/lib/time-range';
import type { SavedSearch } from '@/lib/api';

// NAN-5311: a saved query reopened from the palette ran with the CURRENT
// picker value ("Last hour"), dropping the window it was saved with.

const saved: SavedSearch = {
  id: 'ss_1',
  name: 'soc hunt failed logins',
  query: 'activity_name="Logon" status="Failure"',
  query_mode: 'piped',
  time_range: { start: '2026-01-01T00:00:00.000Z', end: '2026-11-12T00:00:00.000Z' },
  created_at: '2026-11-12T00:00:00.000Z',
  updated_at: '2026-11-12T00:00:00.000Z',
};

afterEach(cleanup);

describe('SavedQueriesPalette time range', () => {
  it('hands the saved window to onSelectQuery', () => {
    const onSelect = vi.fn();
    render(
      <SavedQueriesPalette open onOpenChange={() => {}} savedSearches={[saved]} onSelectQuery={onSelect} />,
    );
    fireEvent.keyDown(screen.getByPlaceholderText(/Search saved queries/), { key: 'Enter' });
    expect(onSelect).toHaveBeenCalledWith(saved.query, 'piped', saved.time_range);
  });

  it('passes no window for a row saved without one', () => {
    const onSelect = vi.fn();
    render(
      <SavedQueriesPalette
        open
        onOpenChange={() => {}}
        savedSearches={[{ ...saved, time_range: undefined }]}
        onSelectQuery={onSelect}
      />,
    );
    fireEvent.keyDown(screen.getByPlaceholderText(/Search saved queries/), { key: 'Enter' });
    expect(onSelect).toHaveBeenCalledWith(saved.query, 'piped', undefined);
  });
});

describe('savedSearchTimeRangeValue', () => {
  it('reopens a stored window as a fixed range', () => {
    expect(savedSearchTimeRangeValue(saved.time_range)).toEqual({
      type: 'custom',
      start: new Date('2026-01-01T00:00:00.000Z'),
      end: new Date('2026-11-12T00:00:00.000Z'),
    });
  });

  it('returns null for a missing or unusable window', () => {
    expect(savedSearchTimeRangeValue(undefined)).toBeNull();
    expect(savedSearchTimeRangeValue(null)).toBeNull();
    expect(savedSearchTimeRangeValue({ start: 'nope', end: '2026-11-12T00:00:00Z' })).toBeNull();
    expect(savedSearchTimeRangeValue({ start: '2026-11-12T00:00:00Z', end: '2026-01-01T00:00:00Z' })).toBeNull();
  });
});

describe('saved search relative presets (NAN-5311)', () => {
  it('stores the preset alongside the resolved window', () => {
    const stored = savedSearchTimeRange({ type: 'preset', preset: 'Last 24 hours' });
    expect(stored.preset).toBe('Last 24 hours');
    const span = new Date(stored.end).getTime() - new Date(stored.start).getTime();
    expect(span).toBe(24 * 60 * 60 * 1000);
  });

  it('stores only the window for a fixed range', () => {
    const start = new Date('2026-01-01T00:00:00.000Z');
    const end = new Date('2026-01-02T00:00:00.000Z');
    expect(savedSearchTimeRange({ type: 'custom', start, end })).toEqual({
      start: start.toISOString(),
      end: end.toISOString(),
    });
  });

  it('reopens a preset relative to now, not on the stale saved window', () => {
    const value = savedSearchTimeRangeValue(
      { start: '2026-01-01T00:00:00.000Z', end: '2026-01-02T00:00:00.000Z', preset: 'Last 24 hours' },
      1234,
    );
    expect(value).toEqual({ type: 'preset', preset: 'Last 24 hours', refreshedAt: 1234 });
  });

  it('falls back to the window for an unknown preset label', () => {
    expect(
      savedSearchTimeRangeValue({ start: '2026-01-01T00:00:00.000Z', end: '2026-01-02T00:00:00.000Z', preset: 'Last eon' }),
    ).toEqual({ type: 'custom', start: new Date('2026-01-01T00:00:00.000Z'), end: new Date('2026-01-02T00:00:00.000Z') });
  });
});
