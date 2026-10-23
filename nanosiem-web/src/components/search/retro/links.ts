// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-4169 — links into RetroView (the intel-hits dossier) from outside Search:
// a retro IOC alert, an IOC list row. `ioc="<v>" | retro` is the summary view
// for one indicator; `ioc in [..] | retro` the per-indicator campaign list.

import { nplQuoted } from '@/lib/npl-quote';

/** The retro IOC hunt's lookback: indicators learned now, matched over 5 days. */
export const RETRO_IOC_WINDOW_DAYS = 5;

const DAY_MS = 24 * 60 * 60 * 1000;
const MINUTE_MS = 60 * 1000;

/** `ioc="<v>" | retro` — the single-indicator RetroView summary. */
export function retroIndicatorQuery(value: string): string {
  return `ioc=${nplQuoted(value)} | retro`;
}

/** `ioc in ["a","b"] | retro` — one per-indicator row each (campaign list). */
export function retroListQuery(values: string[]): string {
  return `ioc in [${values.map(nplQuoted).join(',')}] | retro`;
}

/** The last `days` days ending now, as absolute ISO bounds. */
export function lastDaysRange(days: number = RETRO_IOC_WINDOW_DAYS, now: number = Date.now()): { start: string; end: string } {
  return { start: new Date(now - days * DAY_MS).toISOString(), end: new Date(now).toISOString() };
}

/**
 * Search URL that opens RetroView for one indicator. With `firstSeen`/
 * `lastSeen` (a retro alert's activity window) the range is that window padded
 * by a minute; otherwise the retro IOC window ending now.
 */
export function retroSearchUrl(
  value: string,
  window?: { firstSeen?: string | null; lastSeen?: string | null },
  now: number = Date.now(),
): string {
  const params = new URLSearchParams({ q: retroIndicatorQuery(value) });
  const first = window?.firstSeen ? Date.parse(window.firstSeen) : NaN;
  const last = window?.lastSeen ? Date.parse(window.lastSeen) : NaN;
  let range: { start: string; end: string };
  if (Number.isFinite(first) && Number.isFinite(last) && first <= last) {
    const end = Math.min(now, last + MINUTE_MS);
    range = { start: new Date(Math.min(first - MINUTE_MS, end - MINUTE_MS)).toISOString(), end: new Date(end).toISOString() };
  } else {
    range = lastDaysRange(RETRO_IOC_WINDOW_DAYS, now);
  }
  params.set('start', range.start);
  params.set('end', range.end);
  return `/search#${params.toString()}`;
}

export interface RetroMatch {
  indicator: string;
  feed: string | null;
  learnedAt: string | null;
  firstSeen: string | null;
  lastSeen: string | null;
}

/** NAN-4169: a retro IOC match (an auto retro-hunt hit) carries the indicator
 * and its feed; anything else is an ordinary matched event. */
export function retroMatchOf(event: Record<string, unknown> | undefined): RetroMatch | null {
  if (!event) return null;
  const text = (key: string) => (typeof event[key] === 'string' && event[key] ? (event[key] as string) : null);
  const indicator = text('indicator');
  const isRetro = event.retro_ioc === true || event.retro === true || text('retro_feed') !== null;
  if (!indicator || !isRetro) return null;
  return {
    indicator,
    feed: text('retro_feed'),
    learnedAt: text('retro_learned_at'),
    firstSeen: text('retro_first_seen') ?? text('_first_seen'),
    lastSeen: text('retro_last_seen') ?? text('_last_seen'),
  };
}
