// SPDX-License-Identifier: AGPL-3.0-or-later
import { strict as assert } from 'node:assert';
import { test } from 'vitest';
import { matchSearchWindow, matchSearchUrl, alertSearchUrl } from './search-window';
import { buildMatchView } from './helpers';
import { readTimeRangeParams, toApiTimeRange } from '@/lib/time-range';

const now = new Date('2026-10-17T18:00:00Z');
function view(events: Record<string, unknown>[]) {
  return buildMatchView({ id: 'm', detected_at: '2026-10-17T12:51:44Z', severity: 'high', status: 'open', event_count: events.length, events });
}

test('aggregate bounds include first and last raw events rather than detection time', () => {
  assert.deepEqual(matchSearchWindow(view([{
    first_seen: '2026-10-17 12:40:00.123456', last_seen: '2026-10-17 12:47:57.686000',
    _match_event_time: '2026-10-17 12:47:57.686000',
  }]), 15, now), { start: '2026-10-17T12:25:00.123Z', end: '2026-10-17T12:48:57.686Z' });
});

test('single-event timestamp and numeric OCSF epoch receive default minute padding', () => {
  for (const time of ['2026-10-17T12:47:57Z', Date.parse('2026-10-17T12:47:57Z')]) {
    assert.deepEqual(matchSearchWindow(view([{ time }]), undefined, now), {
      start: '2026-10-17T12:46:57.000Z', end: '2026-10-17T12:48:57.000Z',
    });
  }
});

test('naive microsecond timestamps are UTC independently of viewer timezone', () => {
  const previous = process.env.TZ;
  process.env.TZ = 'America/Los_Angeles';
  try {
    assert.deepEqual(matchSearchWindow(view([{ timestamp: '2026-10-17 12:00:00.999999' }]), 1, now), {
      start: '2026-10-17T11:59:00.999Z', end: '2026-10-17T12:01:00.999Z',
    });
  } finally {
    if (previous === undefined) delete process.env.TZ;
    else process.env.TZ = previous;
  }
});

test('all contributing events determine the bounds and the upper bound is clamped to now', () => {
  assert.deepEqual(matchSearchWindow(view([{ time: '2026-10-17T17:30:00Z' }, { time: '2026-10-17T18:00:00Z' }]), 5, now), {
    start: '2026-10-17T17:25:00.000Z', end: now.toISOString(),
  });
});

test('invalid times fall back to detection time without producing invalid URL bounds', () => {
  assert.deepEqual(matchSearchWindow(view([{ time: 'bad', first_seen: '' }]), 0, now), {
    start: '2026-10-17T12:50:44.000Z', end: '2026-10-17T12:52:44.000Z',
  });
});

test('Search URL round trip retains absolute bounds ahead of a default preset', () => {
  const url = matchSearchUrl('user="a&b"', view([{ time: '2026-10-17T12:00:00Z' }]), 5);
  const params = new URLSearchParams(new URL(url, 'https://example.test').hash.slice(1));
  params.set('time', 'Last hour');
  assert.equal(params.get('q'), 'user="a&b"');
  assert.deepEqual(toApiTimeRange(readTimeRangeParams(params)!), {
    start: '2026-10-17T11:55:00.000Z', end: '2026-10-17T12:01:00.000Z',
  });
  const unselected = new URLSearchParams(new URL(matchSearchUrl('*'), 'https://example.test').hash.slice(1));
  assert.equal(readTimeRangeParams(unselected), null);
});

test('alert events use contributing timestamps and rule lookback, not alert creation', () => {
  const params = new URLSearchParams(new URL(alertSearchUrl('user="a&b"', {
    created_at: '2026-10-17T15:00:00Z',
    matched_events: [{ first_seen: '2026-10-17 12:00:00', last_seen: '2026-10-17 12:05:00' }],
  }, 30), 'https://example.test').hash.slice(1));
  assert.equal(params.get('q'), 'user="a&b"');
  assert.equal(params.get('start'), '2026-10-17T11:30:00.000Z');
  assert.equal(params.get('end'), '2026-10-17T12:06:00.000Z');
});

test('an alert with no contributing timestamps falls back to fired time plus/minus lookback', () => {
  assert.deepEqual(matchSearchWindow(view([]), 15, now), {
    start: '2026-10-17T12:36:44.000Z', end: '2026-10-17T13:06:44.000Z',
  });
});
