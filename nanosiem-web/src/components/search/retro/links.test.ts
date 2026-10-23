// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from 'vitest';
import { lastDaysRange, retroListQuery, retroMatchOf, retroSearchUrl } from './links';

const NOW = Date.parse('2026-10-19T12:00:00Z');

function params(url: string): URLSearchParams {
  expect(url.startsWith('/search#')).toBe(true);
  return new URLSearchParams(url.slice('/search#'.length));
}

describe('retro links (NAN-4169)', () => {
  it('opens RetroView for one indicator over the 5-day retro window', () => {
    const p = params(retroSearchUrl('198.51.100.9:443', undefined, NOW));
    expect(p.get('q')).toBe('ioc="198.51.100.9:443" | retro');
    expect(p.get('start')).toBe('2026-10-14T12:00:00.000Z');
    expect(p.get('end')).toBe('2026-10-19T12:00:00.000Z');
  });

  it("uses a retro alert's activity window, padded and clamped to now", () => {
    const p = params(retroSearchUrl('evil.example', { firstSeen: '2026-10-17T08:00:00Z', lastSeen: '2026-10-18T09:30:00Z' }, NOW));
    expect(p.get('start')).toBe('2026-10-17T07:59:00.000Z');
    expect(p.get('end')).toBe('2026-10-18T09:31:00.000Z');
  });

  it('quotes attacker-authored values', () => {
    expect(params(retroSearchUrl('a"b\\c', undefined, NOW)).get('q')).toBe('ioc="ab\\\\c" | retro');
    expect(retroListQuery(['1.2.3.4', 'x.example'])).toBe('ioc in ["1.2.3.4","x.example"] | retro');
  });

  it('lastDaysRange is absolute', () => {
    expect(lastDaysRange(5, NOW)).toEqual({ start: '2026-10-14T12:00:00.000Z', end: '2026-10-19T12:00:00.000Z' });
  });

  it('recognises retro IOC matches only', () => {
    expect(
      retroMatchOf({ indicator: '1.2.3.4', retro_ioc: true, retro_feed: 'ThreatFox', retro_learned_at: '2026-10-19T10:00:00Z', _first_seen: 'a', _last_seen: 'b' }),
    ).toEqual({ indicator: '1.2.3.4', feed: 'ThreatFox', learnedAt: '2026-10-19T10:00:00Z', firstSeen: 'a', lastSeen: 'b' });
    expect(retroMatchOf({ indicator: '1.2.3.4' })).toBeNull();
    expect(retroMatchOf({ retro: true })).toBeNull();
    expect(retroMatchOf(undefined)).toBeNull();
  });
});
