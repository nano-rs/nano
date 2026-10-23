// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Alert } from '@/lib/api/types';
import type { MatchView } from './helpers';
import { parseTimestampAsUTC } from '@/lib/parse-timestamp-utc';

const MINUTE = 60_000;
const TIME_FIELDS = new Set([
  'first_seen', '_first_seen', 'last_seen', '_last_seen', '_match_event_time',
  'time', 'timestamp', 'eventTime', '_time',
]);

function eventMillis(value: unknown): number {
  if (typeof value === 'string') return parseTimestampAsUTC(value).getTime();
  if (typeof value !== 'number' || !Number.isFinite(value)) return NaN;
  const magnitude = Math.abs(value);
  const millis = magnitude >= 1e17 ? value / 1e6
    : magnitude >= 1e14 ? value / 1e3
      : magnitude >= 1e11 ? value : value * 1e3;
  return new Date(millis).getTime();
}

/** The contributing event window, padded by lookback before and one minute after. */
export function matchSearchWindow(
  view: Pick<MatchView, 'events' | 'detectedAt'>,
  lookbackMinutes?: number,
  now = new Date(),
): { start: string; end: string } | undefined {
  let earliest = Infinity;
  let latest = -Infinity;
  for (const event of view.events) {
    for (const [key, value] of Object.entries(event)) {
      if (!TIME_FIELDS.has(key) && !/^step\d+_(?:time|timestamp)$/.test(key)) continue;
      const millis = eventMillis(value);
      if (!Number.isFinite(millis)) continue;
      earliest = Math.min(earliest, millis);
      latest = Math.max(latest, millis);
    }
  }
  const hasEventTime = Number.isFinite(earliest);
  if (!hasEventTime) earliest = latest = view.detectedAt.getTime();
  if (!Number.isFinite(earliest) || !Number.isFinite(now.getTime())) return undefined;
  const padding = typeof lookbackMinutes === 'number' && Number.isFinite(lookbackMinutes) && lookbackMinutes > 0
    ? Math.max(1, lookbackMinutes) * MINUTE : MINUTE;
  const end = Math.min(now.getTime(), latest + (hasEventTime ? MINUTE : padding));
  const start = Math.min(earliest - padding, end - MINUTE);
  return { start: new Date(start).toISOString(), end: new Date(end).toISOString() };
}

/** Both match actions use the same absolute bounds; no selected match keeps Search's default. */
export function matchSearchUrl(query: string, view?: Pick<MatchView, 'events' | 'detectedAt'> | null, lookbackMinutes?: number): string {
  const params = new URLSearchParams({ q: query });
  const range = view ? matchSearchWindow(view, lookbackMinutes) : undefined;
  if (range) {
    params.set('start', range.start);
    params.set('end', range.end);
  }
  return `/search#${params.toString()}`;
}

/** Alert payloads use matched_events/created_at; keep their pivots on the match policy. */
export function alertSearchUrl(query: string, alert: Pick<Alert, 'matched_events' | 'created_at'>, lookbackMinutes?: number): string {
  return matchSearchUrl(query, {
    events: alert.matched_events ?? [],
    detectedAt: parseTimestampAsUTC(alert.created_at),
  }, lookbackMinutes);
}
